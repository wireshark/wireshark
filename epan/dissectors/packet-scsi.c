/* TODO make the contracts require that all functions be called with valid
 * pointers for itl and itlq and remove all tests for itl/itlq being NULL
 */
/* TODO audit value parameter for proto_tree_add_boolean() calls */
/* packet-scsi.c
 * Routines for decoding SCSI CDBs and responsess
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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

/*
 * Some Notes on using the SCSI Decoder:
 *
 * The SCSI decoder has been built right now so that it is invoked directly by the
 * SCSI transport layers as compared to the standard mechanism of being invoked
 * via a dissector chain. There are multiple reasons for this:
 * - The SCSI CDB is typically embedded inside the transport along with other
 *   header fields that have nothing to do with SCSI. So, it is required to be
 *   done this way.
 * - Originally, Wireshark couldn't do filtering on protocol trees that were not
 *   on the top level.
 *
 * There are four main routines that are provided:
 * o dissect_scsi_cdb - invoked on receiving a SCSI Command
 *   void dissect_scsi_cdb(tvbuff_t *, packet_info *, proto_tree *,
 *                         guint, itlq_nexus_t *, itl_nexus_t *);
 * o dissect_scsi_payload - invoked to decode SCSI responses
 *   void dissect_scsi_payload(tvbuff_t *, packet_info *, proto_tree *, guint,
 *                             gboolean, itlq_nexusu_t *, itl_nexus_t *,
 *                             guint32 relative_offset);
 *   The final parameter is the length of the response field that is negotiated
 *   as part of the SCSI transport layer. If this is not tracked by the
 *   transport, it can be set to 0.
 * o dissect_scsi_rsp - invoked to dissect the scsi status code in a response
 *                      SCSI task.
 *   void dissect_scsi_rsp(tvbuff_t *, packet_info *, proto_tree *,
 *                         itlq_nexus_t *, itl_nexus_t *, guint8);
 * o dissect_scsi_snsinfo - invoked to decode the sense data provided in case of
 *                          an error.
 *   void dissect_scsi_snsinfo(tvbuff_t *, packet_info *, proto_tree *, guint,
 *                             guint, itlq_nexus_t *, itl_nexus_t *);
 *
 * In addition to this, the other requirement made from the transport is to
 * provide ITL and ITLQ structures that are persistent.
 *
 * The ITL structure uniquely identifies a Initiator/Target/Lun combination
 * and is among other things used to keep track of the device type for a
 * specific LUN.
 *
 * The ITLQ structure uniquely identifies a specific scsi task and is used to
 * keep track of OPCODEs between CDB/DATA/Responses and resp[onse times.
 *
 * This decoder attempts to track the type of SCSI device based on the response
 * to the Inquiry command. If the trace does not contain an Inquiry command,
 * the decoding of the commands is done as per a user preference. Currently,
 * only SBC (disks) and SSC (tapes) are the alternatives offered. The basic
 * SCSI command set (SPC-2/3) is decoded for all SCSI devices. If there is a
 * mixture of devices in the trace, some with Inquiry response and some
 * without, the user preference is used only for those devices whose type the
 * decoder has not been able to determine.
 *
 */
#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include "packet-scsi.h"
#include "packet-scsi-osd.h"
#include "packet-scsi-mmc.h"
#include "packet-scsi-sbc.h"
#include "packet-scsi-ssc.h"
#include "packet-scsi-smc.h"

void proto_register_scsi(void);

static int proto_scsi                           = -1;
static int hf_scsi_inq_control_vendor_specific  = -1;
static int hf_scsi_inq_control_reserved         = -1;
static int hf_scsi_inq_control_naca             = -1;
static int hf_scsi_inq_control_obs1             = -1;
static int hf_scsi_inq_control_obs2             = -1;
static int hf_scsi_inq_control                  = -1;
static int hf_scsi_control_vendor_specific      = -1;
static int hf_scsi_control_reserved             = -1;
static int hf_scsi_control_naca                 = -1;
static int hf_scsi_control_obs1                 = -1;
static int hf_scsi_control_obs2                 = -1;
int hf_scsi_control                      = -1;
int hf_scsi_alloclen16                   = -1;
static int hf_scsi_alloclen32                   = -1;
static int hf_scsi_time                         = -1;
static int hf_scsi_request_frame                = -1;
static int hf_scsi_response_frame               = -1;
static int hf_scsi_status                       = -1;
static int hf_scsi_spcopcode                    = -1;
static int hf_scsi_inquiry_flags                = -1;
static int hf_scsi_inquiry_evpd_page            = -1;
static int hf_scsi_inquiry_cmdt_page            = -1;
static int hf_scsi_alloclen                     = -1;
static int hf_scsi_paramlen                     = -1;
static int hf_scsi_paramlen16                   = -1;
static int hf_scsi_modesel_flags                = -1;
static int hf_scsi_modesns_pc                   = -1;
static int hf_scsi_modepage_ps                  = -1;
static int hf_scsi_modepage_spf                 = -1;
static int hf_scsi_modepage_plen                = -1;
static int hf_scsi_modepage_tcmos               = -1;
static int hf_scsi_modepage_scsip               = -1;
static int hf_scsi_modepage_ialuae              = -1;
static int hf_scsi_modepage_icp                 = -1;
static int hf_scsi_modepage_msdl                = -1;
static int hf_scsi_spc_pagecode                 = -1;
static int hf_scsi_spc_subpagecode              = -1;
static int hf_scsi_sbcpagecode                  = -1;
static int hf_scsi_sscpagecode                  = -1;
static int hf_scsi_smcpagecode                  = -1;
static int hf_scsi_mmcpagecode                  = -1;
static int hf_scsi_modesns_flags                = -1;
static int hf_scsi_persresvin_svcaction         = -1;
static int hf_scsi_persresvout_svcaction        = -1;
static int hf_scsi_persresv_scope               = -1;
static int hf_scsi_persresv_type                = -1;
static int hf_scsi_persresvout_reskey           = -1;
static int hf_scsi_persresvout_sareskey         = -1;
static int hf_scsi_persresvout_obsolete         = -1;
static int hf_scsi_persresvout_control          = -1;
static int hf_scsi_persresvout_rel_tpi          = -1;
static int hf_scsi_persresvout_transportid_len  = -1;
static int hf_scsi_persresvout_transportid      = -1;
static int hf_scsi_persresv_control_rsvd        = -1;
static int hf_scsi_persresv_control_rsvd1       = -1;
static int hf_scsi_persresv_control_rsvd2       = -1;
static int hf_scsi_persresv_control_spec_i_pt   = -1;
static int hf_scsi_persresv_control_all_tg_pt   = -1;
static int hf_scsi_persresv_control_aptpl       = -1;
static int hf_scsi_persresv_control_unreg       = -1;
static int hf_scsi_release_flags                = -1;
static int hf_scsi_release_thirdpartyid         = -1;
static int hf_scsi_select_report                = -1;
static int hf_scsi_inq_add_len                  = -1;
static int hf_scsi_inq_peripheral               = -1;
static int hf_scsi_inq_qualifier                = -1;
static int hf_scsi_inq_vendor_id                = -1;
static int hf_scsi_inq_product_id               = -1;
static int hf_scsi_inq_product_rev              = -1;
static int hf_scsi_inq_vendor_specific          = -1;
static int hf_scsi_inq_version_desc             = -1;
static int hf_scsi_inq_devtype                  = -1;
static int hf_scsi_inq_rmb                      = -1;
static int hf_scsi_inq_version                  = -1;
static int hf_scsi_lun_address_mode             = -1;
static int hf_scsi_lun                          = -1;
static int hf_scsi_lun_extended                 = -1;
static int hf_scsi_extended_add_method_len      = -1;
static int hf_scsi_extended_add_method          = -1;
static int hf_scsi_bus                          = -1;
static int hf_scsi_target                       = -1;
static int hf_scsi_modesns_errrep               = -1;
static int hf_scsi_modesns_tst                  = -1;
static int hf_scsi_modesns_qmod                 = -1;
static int hf_scsi_modesns_qerr                 = -1;
static int hf_scsi_modesns_rac                  = -1;
static int hf_scsi_modesns_tas                  = -1;
static int hf_scsi_protocol                     = -1;
static int hf_scsi_sns_errtype                  = -1;
static int hf_scsi_snskey                       = -1;
static int hf_scsi_snsinfo                      = -1;
static int hf_scsi_addlsnslen                   = -1;
static int hf_scsi_asc                          = -1;
static int hf_scsi_ascascq                      = -1;
static int hf_scsi_ascq                         = -1;
static int hf_scsi_fru                          = -1;
static int hf_scsi_sksv                         = -1;
static int hf_scsi_sks_info                     = -1;
static int hf_scsi_sks_fp_cd                    = -1;
static int hf_scsi_sks_fp_bpv                   = -1;
static int hf_scsi_sks_fp_bit                   = -1;
static int hf_scsi_sks_fp_field                 = -1;
static int hf_scsi_sns_desc_type                = -1;
static int hf_scsi_sns_desc_length              = -1;
static int hf_scsi_sns_osd_object_not_initiated = -1;
static int hf_scsi_sns_osd_object_completed     = -1;
static int hf_scsi_sns_osd_object_validation    = -1;
static int hf_scsi_sns_osd_object_cmd_cap_v     = -1;
static int hf_scsi_sns_osd_object_command       = -1;
static int hf_scsi_sns_osd_object_imp_st_att    = -1;
static int hf_scsi_sns_osd_object_sa_cap_v      = -1;
static int hf_scsi_sns_osd_object_set_att       = -1;
static int hf_scsi_sns_osd_object_ga_cap_v      = -1;
static int hf_scsi_sns_osd_object_get_att       = -1;
static int hf_scsi_sns_osd_partition_id         = -1;
static int hf_scsi_sns_osd_object_id            = -1;
static int hf_scsi_sns_osd_attr_page            = -1;
static int hf_scsi_sns_osd_attr_number          = -1;
static int hf_scsi_inq_reladrflags              = -1;
static int hf_scsi_inq_reladr                   = -1;
static int hf_scsi_inq_linked                   = -1;
static int hf_scsi_inq_trandis                  = -1;
static int hf_scsi_inq_cmdque                   = -1;
static int hf_scsi_inq_bqueflags                = -1;
static int hf_scsi_inq_bque                     = -1;
static int hf_scsi_inq_encserv                  = -1;
static int hf_scsi_inq_multip                   = -1;
static int hf_scsi_inq_mchngr                   = -1;
static int hf_scsi_inq_ackreqq                  = -1;
static int hf_scsi_inq_sccsflags                = -1;
static int hf_scsi_inq_sccs                     = -1;
static int hf_scsi_inq_acc                      = -1;
static int hf_scsi_inq_tpc                      = -1;
static int hf_scsi_inq_protect                  = -1;
static int hf_scsi_inq_tpgs                     = -1;
static int hf_scsi_inq_acaflags                 = -1;
static int hf_scsi_inq_rmbflags                 = -1;
static int hf_scsi_inq_normaca                  = -1;
static int hf_scsi_inq_hisup                    = -1;
static int hf_scsi_inq_aerc                     = -1;
static int hf_scsi_inq_trmtsk                   = -1;
static int hf_scsi_inq_rdf                      = -1;
static int hf_scsi_persresv_key                 = -1;
static int hf_scsi_persresv_scopeaddr           = -1;
static int hf_scsi_add_cdblen                   = -1;
static int hf_scsi_svcaction                    = -1;
static int hf_scsi_wb_mode                      = -1;
static int hf_scsi_wb_bufferid                  = -1;
static int hf_scsi_wb_bufoffset                 = -1;
static int hf_scsi_paramlen24                   = -1;
static int hf_scsi_senddiag_st_code             = -1;
static int hf_scsi_senddiag_pf                  = -1;
static int hf_scsi_senddiag_st                  = -1;
static int hf_scsi_senddiag_devoff              = -1;
static int hf_scsi_senddiag_unitoff             = -1;
static int hf_scsi_fragments                    = -1;
static int hf_scsi_fragment                     = -1;
static int hf_scsi_fragment_overlap             = -1;
static int hf_scsi_fragment_overlap_conflict    = -1;
static int hf_scsi_fragment_multiple_tails      = -1;
static int hf_scsi_fragment_too_long_fragment   = -1;
static int hf_scsi_fragment_error               = -1;
static int hf_scsi_fragment_count               = -1;
static int hf_scsi_reassembled_in               = -1;
static int hf_scsi_reassembled_length           = -1;
static int hf_scsi_log_ppc_flags                = -1;
static int hf_scsi_log_pc_flags                 = -1;
static int hf_scsi_log_parameter_ptr            = -1;
static int hf_scsi_log_ppc                      = -1;
static int hf_scsi_log_pcr                      = -1;
static int hf_scsi_log_sp                       = -1;
static int hf_scsi_log_pagecode                 = -1;
static int hf_scsi_log_pc                       = -1;
static int hf_scsi_log_page_length              = -1;
static int hf_scsi_log_parameter_code           = -1;
static int hf_scsi_log_param_len                = -1;
static int hf_scsi_log_param_flags              = -1;
static int hf_scsi_log_param_data               = -1;
static int hf_scsi_log_pf_du                    = -1;
static int hf_scsi_log_pf_ds                    = -1;
static int hf_scsi_log_pf_tsd                   = -1;
static int hf_scsi_log_pf_etc                   = -1;
static int hf_scsi_log_pf_tmc                   = -1;
static int hf_scsi_log_pf_lbin                  = -1;
static int hf_scsi_log_pf_lp                    = -1;
static int hf_scsi_log_ta_rw                    = -1;
static int hf_scsi_log_ta_ww                    = -1;
static int hf_scsi_log_ta_he                    = -1;
static int hf_scsi_log_ta_media                 = -1;
static int hf_scsi_log_ta_rf                    = -1;
static int hf_scsi_log_ta_wf                    = -1;
static int hf_scsi_log_ta_ml                    = -1;
static int hf_scsi_log_ta_ndg                   = -1;
static int hf_scsi_log_ta_wp                    = -1;
static int hf_scsi_log_ta_nr                    = -1;
static int hf_scsi_log_ta_cm                    = -1;
static int hf_scsi_log_ta_uf                    = -1;
static int hf_scsi_log_ta_rmcf                  = -1;
static int hf_scsi_log_ta_umcf                  = -1;
static int hf_scsi_log_ta_mcicf                 = -1;
static int hf_scsi_log_ta_fe                    = -1;
static int hf_scsi_log_ta_rof                   = -1;
static int hf_scsi_log_ta_tdcol                 = -1;
static int hf_scsi_log_ta_nml                   = -1;
static int hf_scsi_log_ta_cn                    = -1;
static int hf_scsi_log_ta_cp                    = -1;
static int hf_scsi_log_ta_ecm                   = -1;
static int hf_scsi_log_ta_ict                   = -1;
static int hf_scsi_log_ta_rr                    = -1;
static int hf_scsi_log_ta_dpie                  = -1;
static int hf_scsi_log_ta_cff                   = -1;
static int hf_scsi_log_ta_psf                   = -1;
static int hf_scsi_log_ta_pc                    = -1;
static int hf_scsi_log_ta_dm                    = -1;
static int hf_scsi_log_ta_hwa                   = -1;
static int hf_scsi_log_ta_hwb                   = -1;
static int hf_scsi_log_ta_if                    = -1;
static int hf_scsi_log_ta_em                    = -1;
static int hf_scsi_log_ta_dwf                   = -1;
static int hf_scsi_log_ta_drhu                  = -1;
static int hf_scsi_log_ta_drtm                  = -1;
static int hf_scsi_log_ta_drvo                  = -1;
static int hf_scsi_log_ta_pefa                  = -1;
static int hf_scsi_log_ta_dire                  = -1;
static int hf_scsi_log_ta_lost                  = -1;
static int hf_scsi_log_ta_tduau                 = -1;
static int hf_scsi_log_ta_tsawf                 = -1;
static int hf_scsi_log_ta_tsarf                 = -1;
static int hf_scsi_log_ta_nsod                  = -1;
static int hf_scsi_log_ta_lofa                  = -1;
static int hf_scsi_log_ta_uuf                   = -1;
static int hf_scsi_log_ta_aif                   = -1;
static int hf_scsi_log_ta_fwf                   = -1;
static int hf_scsi_log_ta_wmicf                 = -1;
static int hf_scsi_log_ta_wmoa                  = -1;
static int hf_scsi_sbc_threshold_exponent       = -1;
static int hf_scsi_sbc_lbpu                     = -1;
static int hf_scsi_sbc_lbpws                    = -1;
static int hf_scsi_sbc_lbpws10                  = -1;
static int hf_scsi_sbc_lbprz                    = -1;
static int hf_scsi_sbc_anc_sup                  = -1;
static int hf_scsi_sbc_dp                       = -1;
static int hf_scsi_sbc_ptype                    = -1;
static int hf_scsi_block_limits_wsnz            = -1;
static int hf_scsi_block_limits_mcawl           = -1;
static int hf_scsi_block_limits_otlg            = -1;
static int hf_scsi_block_limits_mtl             = -1;
static int hf_scsi_block_limits_otl             = -1;
static int hf_scsi_block_limits_mpl             = -1;
static int hf_scsi_block_limits_mulc            = -1;
static int hf_scsi_block_limits_mubdc           = -1;
static int hf_scsi_block_limits_oug             = -1;
static int hf_scsi_block_limits_ugavalid        = -1;
static int hf_scsi_block_limits_uga             = -1;
static int hf_scsi_block_limits_mwsl            = -1;
static int hf_scsi_block_limits_matl            = -1;
static int hf_scsi_block_limits_aa              = -1;
static int hf_scsi_block_limits_atlg            = -1;
static int hf_scsi_prevent_allow_flags          = -1;
static int hf_scsi_prevent_allow_prevent        = -1;
static int hf_scsi_mpi_service_action           = -1;
static int hf_scsi_report_opcodes_rctd          = -1;
static int hf_scsi_report_opcodes_options       = -1;
static int hf_scsi_report_opcodes_requested_o   = -1;
static int hf_scsi_report_opcodes_requested_sa  = -1;
static int hf_scsi_report_opcodes_cdl           = -1;
static int hf_scsi_report_opcodes_sa            = -1;
static int hf_scsi_report_opcodes_ctdp          = -1;
static int hf_scsi_report_opcodes_ctdp_one      = -1;
static int hf_scsi_report_opcodes_servactv      = -1;
static int hf_scsi_report_opcodes_cdb_length    = -1;
static int hf_scsi_report_opcodes_support       = -1;
static int hf_scsi_report_opcodes_cdb_usage_data = -1;
static int hf_scsi_report_opcodes_tdl           = -1;
static int hf_scsi_report_opcodes_npt           = -1;
static int hf_scsi_report_opcodes_rct           = -1;
static int hf_scsi_inquiry_bdc_mrr              = -1;
static int hf_scsi_inquiry_bdc_pt               = -1;
static int hf_scsi_inquiry_bdc_wabereq          = -1;
static int hf_scsi_inquiry_bdc_wacereq          = -1;
static int hf_scsi_inquiry_bdc_nff              = -1;
static int hf_scsi_inquiry_bdc_fuab              = -1;
static int hf_scsi_inquiry_bdc_vbuls            = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_scsi_smc_modepage_first_storage_element_address = -1;
static int hf_scsi_smc_modepage_first_medium_transport_element_address = -1;
static int hf_scsi_ssc2_modepage_dde = -1;
static int hf_scsi_inq_cmddt_version = -1;
static int hf_scsi_mmc5_modepage_number_of_volume_levels_supported = -1;
static int hf_scsi_ssc2_modepage_dce = -1;
static int hf_scsi_modesel_block_descriptor_length16 = -1;
static int hf_scsi_mmc5_modepage_audio_pause_length = -1;
static int hf_scsi_spc_modepage_idle_condition_timer = -1;
static int hf_scsi_blockdescs_block_length24 = -1;
static int hf_scsi_spc_modepage_report_count = -1;
static int hf_scsi_spc_modepage_ready_aer_holdoff_period = -1;
static int hf_scsi_sbc_modepage_non_cache_segment_size = -1;
static int hf_scsi_blockdescs_no_of_blocks64 = -1;
static int hf_scsi_spc_modepage_gltsd = -1;
static int hf_scsi_smc_modepage_st_ne_dt = -1;
static int hf_scsi_modesel_dev_sbc_medium_type = -1;
static int hf_scsi_inq_evpd_devid_identifier_type = -1;
static int hf_scsi_inq_evpd_identifier_number = -1;
static int hf_scsi_sbc_modepage_write_retry_count = -1;
static int hf_scsi_spc_modepage_buffer_empty_ratio = -1;
static int hf_scsi_ssc2_modepage_partition_size = -1;
static int hf_scsi_mmc5_modepage_initiator_application_code = -1;
static int hf_scsi_sbc_modepage_demand_read_retention_priority = -1;
static int hf_scsi_smc_modepage_dt_dt = -1;
static int hf_scsi_sbc_modepage_ssec = -1;
static int hf_scsi_smc_modepage_number_of_medium_transport_elements = -1;
static int hf_scsi_mmc5_modepage_copy_management_revision_support = -1;
static int hf_scsi_ssc2_modepage_maximum_additional_partitions = -1;
static int hf_scsi_blockdescs_density_code = -1;
static int hf_scsi_ssc2_modepage_write_object_buffer_full_ratio = -1;
static int hf_scsi_spc_modepage_rr_tov = -1;
static int hf_scsi_inq_cmddt_support = -1;
static int hf_scsi_mmc5_modepage_packet_size = -1;
static int hf_scsi_ssc2_modepage_fdp = -1;
static int hf_scsi_spc_modepage_autoload_mode = -1;
static int hf_scsi_mmc5_modepage_rw_in_lead_in = -1;
static int hf_scsi_spc_modepage_perf = -1;
static int hf_scsi_inq_evpd_devid_association = -1;
static int hf_scsi_smc_modepage_stordt = -1;
static int hf_scsi_smc_modepage_ie_dt = -1;
static int hf_scsi_spc_modepage_disable_queuing = -1;
static int hf_scsi_sbc_modepage_maximum_pre_fetch_ceiling = -1;
static int hf_scsi_persresvin_generation_number = -1;
static int hf_scsi_ssc2_modepage_read_object_buffer_empty_ratio = -1;
static int hf_scsi_spc_modepage_extended_self_test_completion_time = -1;
static int hf_scsi_smc_modepage_number_of_import_export_elements = -1;
static int hf_scsi_smc_modepage_number_of_storage_elements = -1;
static int hf_scsi_sbc_modepage_landing_zone_cyl = -1;
static int hf_scsi_smc_modepage_mt_ne_dt = -1;
static int hf_scsi_mmc5_modepage_loading_mechanism_type = -1;
static int hf_scsi_smc_modepage_mt_dt = -1;
static int hf_scsi_smc_modepage_first_import_export_element_address = -1;
static int hf_scsi_mmc5_modepage_link_size = -1;
static int hf_scsi_ssc2_modepage_decompression_algorithm = -1;
static int hf_scsi_reportluns_lun_list_length = -1;
static int hf_scsi_spc_modepage_idle = -1;
static int hf_scsi_spc_modepage_emdp = -1;
static int hf_scsi_inq_evpd_devid_code_set = -1;
static int hf_scsi_modesel_longlba = -1;
static int hf_scsi_mmc5_modepage_bufe = -1;
static int hf_scsi_ssc2_modepage_select_data_compression_algorithm = -1;
static int hf_scsi_mmc5_modepage_rotation_control_selected = -1;
static int hf_scsi_mmc5_modepage_sub_header_byte = -1;
static int hf_scsi_spc_modepage_rr_tov_units = -1;
static int hf_scsi_mmc5_modepage_vendor_specific = -1;
static int hf_scsi_modesel_block_descriptor_length8 = -1;
static int hf_scsi_smc_modepage_ie_ne_dt = -1;
static int hf_scsi_modesel_device_specific_parameter = -1;
static int hf_scsi_spc_modepage_connect_time_limit = -1;
static int hf_scsi_sbc_modepage_medium_rotation_rate = -1;
static int hf_scsi_inq_evpd_devid_identifier_length = -1;
static int hf_scsi_blockdescs_no_of_blocks32 = -1;
static int hf_scsi_inq_evpd_devid_identifier_str = -1;
static int hf_scsi_sns_valid = -1;
static int hf_scsi_mmc5_modepage_dvd_ram_read = -1;
static int hf_scsi_ssc2_modepage_gap_size = -1;
static int hf_scsi_smc_modepage_first_data_transfer_element_address = -1;
static int hf_scsi_mmc5_modepage_wrparam_multi_session = -1;
static int hf_scsi_mmc5_modepage_num_write_speed_performance = -1;
static int hf_scsi_mmc5_modepage_buf = -1;
static int hf_scsi_mmc5_modepage_lba_space = -1;
static int hf_scsi_mmc5_modepage_data_block_type = -1;
static int hf_scsi_ssc2_modepage_additional_partitions_defined = -1;
static int hf_scsi_spc_modepage_dtfd = -1;
static int hf_scsi_spc_modepage_disconnect_time_limit = -1;
static int hf_scsi_sbc_modepage_read_retry_count = -1;
static int hf_scsi_mmc5_modepage_length = -1;
static int hf_scsi_sns_filemark = -1;
static int hf_scsi_sbc_modepage_alternate_tracks_per_zone = -1;
static int hf_scsi_ssc2_modepage_eod_defined = -1;
static int hf_scsi_mmc5_modepage_media_catalog_number = -1;
static int hf_scsi_mmc5_modepage_current_write_speed_selected = -1;
static int hf_scsi_inq_evpd_devid_identifier_bytes = -1;
static int hf_scsi_spc_modepage_interval_timer = -1;
static int hf_scsi_ssc2_modepage_oir = -1;
static int hf_scsi_sbc_modepage_correction_span = -1;
static int hf_scsi_mmc5_modepage_session_format = -1;
static int hf_scsi_sbc_modepage_minimum_pre_fetch = -1;
static int hf_scsi_spc_modepage_maximum_burst_size = -1;
static int hf_scsi_ssc2_modepage_partition_units = -1;
static int hf_scsi_sbc_modepage_cache_segment_size = -1;
static int hf_scsi_blockdescs_block_length32 = -1;
static int hf_scsi_sbc_modepage_number_of_cylinders = -1;
static int hf_scsi_sbc_modepage_alternate_tracks_per_lu = -1;
static int hf_scsi_inq_evpd_page_length = -1;
static int hf_scsi_sbc_modepage_starting_cyl_pre_compensation = -1;
static int hf_scsi_sbc_modepage_head_offset_count = -1;
static int hf_scsi_sbc_modepage_ic = -1;
static int hf_scsi_modesel_mode_data_length16 = -1;
static int hf_scsi_sbc_modepage_maximum_pre_fetch = -1;
static int hf_scsi_smc_modepage_number_of_data_transfer_elements = -1;
static int hf_scsi_ssc2_modepage_object_buffer_size_at_early_warning = -1;
static int hf_scsi_mmc5_modepage_buffer_size_supported = -1;
static int hf_scsi_persresvin_additional_length = -1;
static int hf_scsi_ssc2_modepage_obr = -1;
static int hf_scsi_spc_modepage_swp = -1;
static int hf_scsi_inq_evpd_supported_page = -1;
static int hf_scsi_sbc_modepage_awre = -1;
static int hf_scsi_smc_modepage_dt_ne_dt = -1;
static int hf_scsi_mmc5_modepage_read_bar_code = -1;
static int hf_scsi_ssc2_modepage_media_format_recognition = -1;
static int hf_scsi_sns_command_specific_information = -1;
static int hf_scsi_ssc2_modepage_write_delay_time = -1;
static int hf_scsi_sbc_modepage_track_skew_factor = -1;
static int hf_scsi_spc_modepage_standby_condition_timer = -1;
static int hf_scsi_sbc_modepage_interleave = -1;
static int hf_scsi_sbc_modepage_alternate_sectors_per_zone = -1;
static int hf_scsi_sbc_modepage_rotational_offset = -1;
static int hf_scsi_spc_modepage_buffer_full_ratio = -1;
static int hf_scsi_sbc_modepage_number_of_heads = -1;
static int hf_scsi_sbc_modepage_sectors_per_track = -1;
static int hf_scsi_sbc_modepage_recovery_time_limit = -1;
static int hf_scsi_sbc_modepage_tracks_per_zone = -1;
static int hf_scsi_spc_modepage_first_burst_size = -1;
static int hf_scsi_inq_evpd_product_serial_number = -1;
static int hf_scsi_sbc_modepage_cylinder_skew_factor = -1;
static int hf_scsi_sbc_modepage_data_bytes_per_physical_sector = -1;
static int hf_scsi_ssc2_modepage_compression_algorithm = -1;
static int hf_scsi_ssc2_modepage_caf = -1;
static int hf_scsi_sbc_modepage_starting_cyl_reduced_write_current = -1;
static int hf_scsi_inq_cmddt_cdb_size = -1;
static int hf_scsi_mmc5_modepage_international_standard_recording_code = -1;
static int hf_scsi_spc_modepage_bus_inactivity_limit = -1;
static int hf_scsi_sbc_modepage_disable_pre_fetch_xfer_len = -1;
static int hf_scsi_spc_modepage_busy_timeout_period = -1;
static int hf_scsi_sbc_modepage_fsw = -1;
static int hf_scsi_ssc2_modepage_active_partition = -1;
static int hf_scsi_modesel_mode_data_length8 = -1;
static int hf_scsi_smc_modepage_st_dt = -1;
static int hf_scsi_sbc_modepage_number_of_cache_segments = -1;
static int hf_scsi_blockdescs_no_of_blocks24 = -1;
static int hf_scsi_sbc_modepage_data_strobe_offset_count = -1;
static int hf_scsi_modesel_medium_type = -1;
static int hf_scsi_sbc_modepage_device_step_rate = -1;
static int hf_scsi_mmc5_modepage_dvd_ram_write = -1;
static int hf_scsi_mmc5_modepage_track_mode = -1;
static int hf_scsi_smc_modepage_mt_ne_mt = -1;
static int hf_scsi_smc_modepage_dt_mt = -1;
static int hf_scsi_mmc5_modepage_eject = -1;
static int hf_scsi_mmc5_modepage_mode_2_form2 = -1;
static int hf_scsi_sbc_modepage_dra = -1;
static int hf_scsi_mmc5_modepage_dvd_rom_write = -1;
static int hf_scsi_sbc_modepage_eer = -1;
static int hf_scsi_mmc5_modepage_cd_da_cmds_supported = -1;
static int hf_scsi_smc_modepage_ie_ne_mt = -1;
static int hf_scsi_mmc5_modepage_rw_deinterleaved_corrected = -1;
static int hf_scsi_sbc_modepage_vendor_specific = -1;
static int hf_scsi_spc_modepage_report_log_exception_condition = -1;
static int hf_scsi_mmc5_modepage_c2_pointers_supported = -1;
static int hf_scsi_mmc5_modepage_ls_v = -1;
static int hf_scsi_sbc_modepage_tb = -1;
static int hf_scsi_sbc_modepage_write_retention_priority = -1;
static int hf_scsi_smc_modepage_mt_ne_ie = -1;
static int hf_scsi_ssc2_modepage_prmwp = -1;
static int hf_scsi_sbc_modepage_surf = -1;
static int hf_scsi_sns_ili = -1;
static int hf_scsi_smc_modepage_mt_ie = -1;
static int hf_scsi_sbc_modepage_rcd = -1;
static int hf_scsi_mmc5_modepage_composite = -1;
static int hf_scsi_sbc_modepage_wce = -1;
static int hf_scsi_mmc5_modepage_method_2 = -1;
static int hf_scsi_ssc2_modepage_clear = -1;
static int hf_scsi_sbc_modepage_lbcss = -1;
static int hf_scsi_mmc5_modepage_cd_r_read = -1;
static int hf_scsi_spc_modepage_test = -1;
static int hf_scsi_ssc2_modepage_rsmk = -1;
static int hf_scsi_spc_modepage_rha = -1;
static int hf_scsi_mmc5_modepage_lsbf = -1;
static int hf_scsi_mmc5_modepage_cd_rw_write = -1;
static int hf_scsi_mmc5_modepage_wrparam_test_write = -1;
static int hf_scsi_ssc2_modepage_eeg = -1;
static int hf_scsi_mmc5_modepage_digital_port2 = -1;
static int hf_scsi_mmc5_modepage_copy = -1;
static int hf_scsi_sbc_modepage_abpf = -1;
static int hf_scsi_spc_modepage_alwi = -1;
static int hf_scsi_mmc5_modepage_bckf = -1;
static int hf_scsi_ssc2_modepage_dsp = -1;
static int hf_scsi_mmc5_modepage_mode_2_form1 = -1;
static int hf_scsi_smc_modepage_stormt = -1;
static int hf_scsi_mmc5_modepage_mmcap_test_write = -1;
static int hf_scsi_smc_modepage_st_mt = -1;
static int hf_scsi_ssc2_modepage_sew = -1;
static int hf_scsi_ssc2_modepage_psum = -1;
static int hf_scsi_mmc5_modepage_dvd_r_read = -1;
static int hf_scsi_ssc2_modepage_asocwp = -1;
static int hf_scsi_smc_modepage_st_ie = -1;
static int hf_scsi_mmc5_modepage_cd_rw_read = -1;
static int hf_scsi_spc_modepage_standby = -1;
static int hf_scsi_spc_modepage_ewasc = -1;
static int hf_scsi_sbc_modepage_arre = -1;
static int hf_scsi_smc_modepage_st_st = -1;
static int hf_scsi_ssc2_modepage_swp = -1;
static int hf_scsi_smc_modepage_storie = -1;
static int hf_scsi_mmc5_modepage_fp = -1;
static int hf_scsi_ssc2_modepage_red = -1;
static int hf_scsi_ssc2_modepage_active_format = -1;
static int hf_scsi_mmc5_modepage_mmcap_multi_session = -1;
static int hf_scsi_mmc5_modepage_lock_state = -1;
static int hf_scsi_mmc5_modepage_side_change_capable = -1;
static int hf_scsi_mmc5_modepage_dvd_rom_read = -1;
static int hf_scsi_sns_eom = -1;
static int hf_scsi_sbc_modepage_rc = -1;
static int hf_scsi_mmc5_modepage_lock = -1;
static int hf_scsi_sbc_modepage_per = -1;
static int hf_scsi_ssc2_modepage_socf = -1;
static int hf_scsi_sbc_modepage_mf = -1;
static int hf_scsi_smc_modepage_ie_st = -1;
static int hf_scsi_mmc5_modepage_digital_port1 = -1;
static int hf_scsi_sbc_modepage_hsec = -1;
static int hf_scsi_sbc_modepage_cap = -1;
static int hf_scsi_smc_modepage_st_ne_ie = -1;
static int hf_scsi_spc_modepage_logerr = -1;
static int hf_scsi_sbc_modepage_rmb = -1;
static int hf_scsi_mmc5_modepage_prevent_jumper = -1;
static int hf_scsi_smc_modepage_ie_mt = -1;
static int hf_scsi_mmc5_modepage_changer_supports_disc_present = -1;
static int hf_scsi_mmc5_modepage_cd_r_write = -1;
static int hf_scsi_ssc2_modepage_addp = -1;
static int hf_scsi_mmc5_modepage_dvd_r_write = -1;
static int hf_scsi_spc_modepage_dexcpt = -1;
static int hf_scsi_spc_modepage_ebf = -1;
static int hf_scsi_mmc5_modepage_write_type = -1;
static int hf_scsi_spc_modepage_fab = -1;
static int hf_scsi_smc_modepage_ie_ne_st = -1;
static int hf_scsi_ssc2_modepage_baml = -1;
static int hf_scsi_smc_modepage_storst = -1;
static int hf_scsi_sbc_modepage_dte = -1;
static int hf_scsi_mmc5_modepage_separate_volume_levels = -1;
static int hf_scsi_mmc5_modepage_isrc = -1;
static int hf_scsi_smc_modepage_dt_ne_mt = -1;
static int hf_scsi_mmc5_modepage_audio_play = -1;
static int hf_scsi_mmc5_modepage_separate_channel_mute = -1;
static int hf_scsi_ssc2_modepage_rew = -1;
static int hf_scsi_sbc_modepage_dcr = -1;
static int hf_scsi_smc_modepage_dt_ie = -1;
static int hf_scsi_ssc2_modepage_avc = -1;
static int hf_scsi_sbc_modepage_size = -1;
static int hf_scsi_mmc5_modepage_rw_supported = -1;
static int hf_scsi_spc_modepage_dtipe = -1;
static int hf_scsi_mmc5_modepage_sw_slot_selection = -1;
static int hf_scsi_ssc2_modepage_pofm = -1;
static int hf_scsi_spc_modepage_dlm = -1;
static int hf_scsi_spc_modepage_plpb = -1;
static int hf_scsi_smc_modepage_st_ne_st = -1;
static int hf_scsi_smc_modepage_dt_ne_st = -1;
static int hf_scsi_smc_modepage_st_ne_mt = -1;
static int hf_scsi_ssc2_modepage_robo = -1;
static int hf_scsi_spc_modepage_faa = -1;
static int hf_scsi_spc_modepage_ddis = -1;
static int hf_scsi_mmc5_modepage_cd_da_stream_is_accurate = -1;
static int hf_scsi_ssc2_modepage_bam = -1;
static int hf_scsi_spc_modepage_fac = -1;
static int hf_scsi_smc_modepage_mt_st = -1;
static int hf_scsi_smc_modepage_ie_ie = -1;
static int hf_scsi_smc_modepage_dt_ne_ie = -1;
static int hf_scsi_ssc2_modepage_lois = -1;
static int hf_scsi_spc_modepage_dtoli = -1;
static int hf_scsi_sbc_modepage_disc = -1;
static int hf_scsi_smc_modepage_ie_ne_ie = -1;
static int hf_scsi_smc_modepage_mt_ne_st = -1;
static int hf_scsi_ssc2_modepage_dcc = -1;
static int hf_scsi_mmc5_modepage_rck = -1;
static int hf_scsi_smc_modepage_mt_mt = -1;
static int hf_scsi_smc_modepage_dt_st = -1;
static int hf_scsi_ssc2_modepage_rewind_on_reset = -1;
static int hf_scsi_mmc5_modepage_upc = -1;
static int hf_scsi_ssc2_modepage_idp = -1;
static int hf_scsi_ssc2_modepage_perswp = -1;
static int hf_scsi_spc_xcopy_service = -1;
static int hf_scsi_spc_recv_copy_service = -1;
static int hf_scsi_spc_xcopy_param_list_len = -1;
static int hf_scsi_spc_xcopy_param_list_format = -1;
static int hf_scsi_spc_xcopy_cscd_desc_list_len = -1;
static int hf_scsi_spc_xcopy_head_cscd_desc_list_len = -1;
static int hf_scsi_spc_xcopy_head_cscd_desc_type_code = -1;
static int hf_scsi_spc_xcopy_cscd_desc_type_code = -1;
static int hf_scsi_spc_xcopy_inline_data_len = -1;
static int hf_scsi_spc_xcopy_seg_desc_list_len = -1;
static int hf_scsi_spc_xcopy_list_id = -1;
static int hf_scsi_spc_xcopy_rel_init_port_id = -1;
static int hf_scsi_spc_xcopy_per_dev_type_byte = -1;
static int hf_scsi_spc_xcopy_per_dev_type = -1;
static int hf_scsi_spc_xcopy_lu_type = -1;
static int hf_scsi_spc_xcopy_disk_block_len = -1;
static int hf_scsi_spc_xcopy_cscd_desc_code_set = -1;
static int hf_scsi_spc_xcopy_cscd_desc_assoc = -1;
static int hf_scsi_spc_xcopy_cscd_desc_des_type = -1;
static int hf_scsi_spc_xcopy_cscd_desc_des_len = -1;
static int hf_scsi_spc_xcopy_seg_desc_type = -1;
static int hf_scsi_spc_xcopy_seg_desc_dc = -1;
static int hf_scsi_spc_xcopy_seg_desc_cat = -1;
static int hf_scsi_spc_xcopy_seg_des_src_desc_id = -1;
static int hf_scsi_spc_xcopy_seg_des_dest_desc_id = -1;
static int hf_scsi_spc_xcopy_num_of_blocks = -1;
static int hf_scsi_spc_xcopy_param_list_id_usage = -1;
static int hf_scsi_spc_xcopy_param_str = -1;
static int hf_scsi_spc_xcopy_param_priority = -1;
static int hf_scsi_spc_xcopy_param_byte = -1;
static int hf_scsi_spc_xcopy_source_lba = -1;
static int hf_scsi_spc_xcopy_dest_lba = -1;
static int hf_scsi_recv_copy_max_cscd_desc_count = -1;
static int hf_scsi_recv_copy_max_seg_desc_count = -1;
static int hf_scsi_recv_copy_max_desc_list_len = -1;
static int hf_scsi_recv_copy_max_seg_len = -1;
static int hf_scsi_recv_copy_max_inline_data_len = -1;
static int hf_scsi_recv_copy_held_data_limit = -1;
static int hf_scsi_recv_copy_max_stream_dev_trans_size = -1;
static int hf_scsi_recv_copy_snlid = -1;
static int hf_scsi_recv_copy_avail_data = -1;
static int hf_scsi_recv_copy_total_con_copies = -1;
static int hf_scsi_recv_copy_max_con_copies = -1;
static int hf_scsi_recv_copy_data_seg_gran = -1;
static int hf_scsi_recv_copy_inline_data_gran = -1;
static int hf_scsi_recv_copy_held_data_gran = -1;
static int hf_scsi_recv_copy_implemented_desc_list_len = -1;
static int hf_scsi_segment_descriptor_length = -1;
static int hf_scsi_designator = -1;
static int hf_scsi_inline_data = -1;
static int hf_scsi_reserved_8 = -1;
static int hf_scsi_reserved_16 = -1;
static int hf_scsi_reserved_24 = -1;
static int hf_scsi_reserved_32 = -1;
static int hf_scsi_reserved_64 = -1;
static int hf_scsi_naa_type = -1;
static int hf_scsi_naa_locally_assigned = -1;
static int hf_scsi_naa_ieee_company_id = -1;
static int hf_scsi_naa_vendor_specific = -1;
static int hf_scsi_naa_vendor_specific_extension = -1;

static gint ett_scsi = -1;
static gint ett_scsi_page = -1;
gint ett_scsi_control = -1;
static gint ett_scsi_inq_control = -1;
static gint ett_scsi_inq_peripheral = -1;
static gint ett_scsi_inq_acaflags = -1;
static gint ett_scsi_inq_rmbflags = -1;
static gint ett_scsi_inq_sccsflags = -1;
static gint ett_scsi_inq_bqueflags = -1;
static gint ett_scsi_inq_reladrflags = -1;
static gint ett_scsi_log = -1;
static gint ett_scsi_log_ppc = -1;
static gint ett_scsi_log_pc = -1;
static gint ett_scsi_log_param = -1;
static gint ett_scsi_fragments = -1;
static gint ett_scsi_fragment = -1;
static gint ett_persresv_control = -1;
static gint ett_scsi_lun = -1;
static gint ett_scsi_lun_unit = -1;
static gint ett_scsi_prevent_allow = -1;
static gint ett_command_descriptor = -1;
static gint ett_timeout_descriptor = -1;
static gint ett_sense_descriptor = -1;
static gint ett_sense_osd_not_initiated = -1;
static gint ett_sense_osd_completed = -1;
static gint ett_xcopy_per_dev_type = -1;
static gint ett_xcopy_param_byte = -1;
static gint ett_scsi_xcopy_cscds = -1;
static gint ett_scsi_xcopy_cscd = -1;
static gint ett_scsi_xcopy_dev_params = -1;
static gint ett_scsi_xcopy_segs = -1;
static gint ett_scsi_xcopy_seg = -1;
static gint ett_scsi_xcopy_seg_param = -1;
static gint ett_scsi_cscd_desc = -1;
static gint ett_scsi_naa = -1;
static gint ett_scsi_designation_descriptor = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_scsi_unknown_scsi_exchange = EI_INIT;
static expert_field ei_scsi_product_data_goes_past_end_of_page = EI_INIT;
static expert_field ei_scsi_unknown_page = EI_INIT;
static expert_field ei_scsi_no_dissection_for_service_action = EI_INIT;
static expert_field ei_scsi_unknown_serv_action = EI_INIT;

static int scsi_tap = -1;

/* Defragment of SCSI DATA IN/OUT */
static gboolean scsi_defragment = FALSE;

static reassembly_table scsi_reassembly_table;

/*
 * Required by all commands
 */
const int *cdb_control_fields[6] = {
    &hf_scsi_control_vendor_specific,
    &hf_scsi_control_reserved,
    &hf_scsi_control_naca,
    &hf_scsi_control_obs1,
    &hf_scsi_control_obs2,
    NULL
};

static void
scsi_defragment_init(void)
{
    reassembly_table_init(&scsi_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
scsi_defragment_cleanup(void)
{
    reassembly_table_destroy(&scsi_reassembly_table);
}

static const fragment_items scsi_frag_items = {
    &ett_scsi_fragment,
    &ett_scsi_fragments,
    &hf_scsi_fragments,
    &hf_scsi_fragment,
    &hf_scsi_fragment_overlap,
    &hf_scsi_fragment_overlap_conflict,
    &hf_scsi_fragment_multiple_tails,
    &hf_scsi_fragment_too_long_fragment,
    &hf_scsi_fragment_error,
    &hf_scsi_fragment_count,
    &hf_scsi_reassembled_in,
    &hf_scsi_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};


typedef guint32 scsi_cmnd_type;
typedef guint32 scsi_device_type;

/* Valid SCSI Command Types */
#define SCSI_CMND_SPC                    1
#define SCSI_CMND_SBC                    2
#define SCSI_CMND_SSC                    3
#define SCSI_CMND_SMC                    4
#define SCSI_CMND_MMC                    5

/* SPC and SPC-2 Commands */
static const value_string scsi_spc_vals[] = {
    /* 0x00 */    {SCSI_SPC_TESTUNITRDY        , "Test Unit Ready"},
    /* 0x03 */    {SCSI_SPC_REQSENSE           , "Request Sense"},
    /* 0x12 */    {SCSI_SPC_INQUIRY            , "Inquiry"},
    /* 0x15 */    {SCSI_SPC_MODESELECT6        , "Mode Select(6)"},
    /* 0x16 */    {SCSI_SPC_RESERVE6           , "Reserve(6)"},
    /* 0x17 */    {SCSI_SPC_RELEASE6           , "Release(6)"},
    /* 0x18 */    {SCSI_SPC_COPY               , "Copy"},
    /* 0x1A */    {SCSI_SPC_MODESENSE6         , "Mode Sense(6)"},
    /* 0x1C */    {SCSI_SPC_RCVDIAGRESULTS     , "Receive Diagnostics Results"},
    /* 0x1D */    {SCSI_SPC_SENDDIAG           , "Send Diagnostic"},
    /* 0x1E */    {SCSI_SPC_PREVMEDREMOVAL     , "Prevent/Allow Medium Removal"},
    /* 0x39 */    {SCSI_SPC_COMPARE            , "Compare"},
    /* 0x3A */    {SCSI_SPC_COPY_AND_VERIFY    , "Copy And Verify"},
    /* 0x3B */    {SCSI_SPC_WRITEBUFFER        , "Write Buffer"},
    /* 0x3C */    {SCSI_SPC_READBUFFER         , "Read Buffer"},
    /* 0x40 */    {SCSI_SPC_CHANGE_DEFINITION  , "Change Definition"},
    /* 0x4C */    {SCSI_SPC_LOGSELECT          , "Log Select"},
    /* 0x4D */    {SCSI_SPC_LOGSENSE           , "Log Sense"},
    /* 0x55 */    {SCSI_SPC_MODESELECT10       , "Mode Select(10)"},
    /* 0x56 */    {SCSI_SPC_RESERVE10          , "Reserve(10)"},
    /* 0x57 */    {SCSI_SPC_RELEASE10          , "Release(10)"},
    /* 0x5A */    {SCSI_SPC_MODESENSE10        , "Mode Sense(10)"},
    /* 0x5E */    {SCSI_SPC_PERSRESVIN         , "Persistent Reserve In"},
    /* 0x5F */    {SCSI_SPC_PERSRESVOUT        , "Persistent Reserve Out"},
    /* 0x7F */    {SCSI_SPC_VARLENCDB          , "Variable Length CDB"},
    /* 0x83 */    {SCSI_SPC_EXTCOPY            , "Extended Copy"},
    /* 0x84 */    {SCSI_SPC_RECVCOPY           , "Receive Copy"},
    /* 0x84 */    {SCSI_SPC_RCVCOPYRESULTS     , "Receive Copy Results"},
    /* 0x86 */    {SCSI_SPC_ACCESS_CONTROL_IN  , "Access Control In"},
    /* 0x87 */    {SCSI_SPC_ACCESS_CONTROL_OUT , "Access Control Out"},
    /* 0xA0 */    {SCSI_SPC_REPORTLUNS         , "Report LUNs"},
    /* 0xA3 */    {SCSI_SPC_MGMT_PROTOCOL_IN   , "Mgmt Protocol In"},
    {0, NULL},
};
static value_string_ext scsi_spc_vals_ext = VALUE_STRING_EXT_INIT(scsi_spc_vals);

static const value_string scsi_lun_address_mode_vals[] = {
    { 0, "Peripheral Device Addressing Method" },
    { 1, "Flat Space Addressing Method" },
    { 2, "Logical Unit Addressing Method" },
    { 3, "Extended Logical Unit Addressing" },
    { 0, NULL }
};

static const value_string provisioning_vals[] = {
    {0, "No provisioning"},
    {1, "Resource provisioned"},
    {2, "Thin provisioned"},
    {0, NULL},
};

static const value_string log_flags_tmc_vals[] = {
    {0, "Every update of the cumulative value"},
    {1, "Cumulative value equal to threshold value"},
    {2, "Cumulative value not equal to threshold value"},
    {3, "Cumulative value greater than threshold value"},
    {0, NULL},
};

static const value_string scsi_select_report_val[] = {
    {0, "Select All LUNs" },
    {1, "Select Well-Known LUNs" },
    {2, "Select All LUNs accessible to this I_T nexus" },
    {0, NULL},
};

#define SCSI_EVPD_SUPPPG          0x00
#define SCSI_EVPD_DEVSERNUM       0x80
#define SCSI_EVPD_OPER            0x81
#define SCSI_EVPD_ASCIIOPER       0x82
#define SCSI_EVPD_DEVID           0x83
#define SCSI_EVPD_BLKLIMITS       0xb0
#define SCSI_EVPD_BLKDEVCHAR      0xb1
#define SCSI_EVPD_LBP             0xb2

static const value_string scsi_evpd_pagecode_val[] = {
    {SCSI_EVPD_SUPPPG,    "Supported Vital Product Data Pages"},
    {0x01,                "ASCII Information Page"},
    {0x02,                "ASCII Information Page"},
    {0x03,                "ASCII Information Page"},
    {0x04,                "ASCII Information Page"},
    {0x05,                "ASCII Information Page"},
    {0x06,                "ASCII Information Page"},
    {0x07,                "ASCII Information Page"},
    /* XXX - 0x01 through 0x7F are all ASCII information pages */
    {SCSI_EVPD_DEVSERNUM, "Unit Serial Number Page"},
    {SCSI_EVPD_OPER,      "Implemented Operating Definition Page"},
    {SCSI_EVPD_ASCIIOPER, "ASCII Implemented Operating Definition Page"},
    {SCSI_EVPD_DEVID,     "Device Identification Page"},
    {SCSI_EVPD_BLKLIMITS, "Block Limits Page"},
    {SCSI_EVPD_BLKDEVCHAR,"Block Device Characteristics"},
    {SCSI_EVPD_LBP,       "Logical Block Provisioning Page"},
    {0, NULL},
};

static const value_string mrr_val[] = {
    {0x0,       "Media rotation speed not reported"},
    {0x1,       "Non-rotating media"},
    /* 0x2 - 0x400 - reserved */
    {5400,      "5,400 RPM"},
    {7200,      "7,200 RPM"},
    {10000,     "10,000 RPM"},
    {15000,     "15,000 RPM"},
    {0, NULL},
};
static const value_string scsi_log_pc_val[] = {
    {0, "Threshold Values"},
    {1, "Cumulative Values"},
    {2, "Default Threshold Values"},
    {3, "Default Cumulative Values"},
    {0, NULL},
};

#define NAA_TYPE_IEEE_EXTENDED            2
#define NAA_TYPE_LOCALLY_ASSIGNED         3
#define NAA_TYPE_IEEE_REGISTERED          5
#define NAA_TYPE_IEEE_REGISTERED_EXTENDED 6
static const value_string scsi_naa_designator_type_val[] = {
    {2, "IEEE Extended" },
    {3, "Locally Assigned" },
    {5, "IEEE Registered" },
    {6, "IEEE Registered Extended" },
    {0, NULL},
};

#define SCSI_NUM_PROCEDURES 256
typedef struct scsistat_tap_data
{
    guint8     cmdset;
    const char *prog;
    value_string_ext *cdbnames_ext;
    const char *hf_name;
} scsistat_tap_data_t;

static void
scsistat_init(struct register_srt* srt, GArray* srt_array, srt_gui_init_cb gui_callback, void* gui_data)
{
    scsistat_tap_data_t* tap_data = (scsistat_tap_data_t*)get_srt_table_param_data(srt);
    srt_stat_table *scsi_srt_table;
    guint32 i;

    DISSECTOR_ASSERT(tap_data);

    scsi_srt_table = init_srt_table(tap_data->prog, NULL, srt_array, SCSI_NUM_PROCEDURES, NULL, tap_data->hf_name, gui_callback, gui_data, tap_data);
    for (i = 0; i < SCSI_NUM_PROCEDURES; i++)
    {
        init_srt_table_row(scsi_srt_table, i, val_to_str_ext_const(i, tap_data->cdbnames_ext, "Unknown-0x%02x"));
    }
}

static int
scsistat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
    guint i = 0;
    srt_stat_table *scsi_srt_table;
    srt_data_t *data = (srt_data_t *)pss;
    const scsi_task_data_t *ri = (const scsi_task_data_t *)prv;
    scsistat_tap_data_t* tap_data;

    scsi_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
    tap_data = (scsistat_tap_data_t*)scsi_srt_table->table_specific_data;

    /* we are only interested in response packets */
    if (ri->type != SCSI_PDU_TYPE_RSP) {
        return 0;
    }
    /* we are only interested in a specific commandset */
    if ( (!ri->itl) || ((ri->itl->cmdset&SCSI_CMDSET_MASK) != tap_data->cmdset) ) {
        return 0;
    }
    /* check that the opcode looks sane */
    if ( (!ri->itlq) || (ri->itlq->scsi_opcode > 255) ) {
        return 0;
    }

    add_srt_table_data(scsi_srt_table, ri->itlq->scsi_opcode, &ri->itlq->fc_time, pinfo);
    return 1;
}

static guint
scsistat_param(register_srt_t* srt, const char* opt_arg, char** err)
{
    int pos = 0;
    int program;
    scsistat_tap_data_t* tap_data;

    if (sscanf(opt_arg, ",%d%n", &program, &pos) == 1)
    {
        tap_data = g_new0(scsistat_tap_data_t, 1);
        tap_data->cmdset = (guint8)program;

        switch(program){
        case SCSI_DEV_SBC:
            tap_data->prog = "SBC (disk)";
            tap_data->cdbnames_ext = &scsi_sbc_vals_ext;
            tap_data->hf_name = "scsi_sbc.opcode";
        break;
        case SCSI_DEV_SSC:
            tap_data->prog = "SSC (tape)";
            tap_data->cdbnames_ext = &scsi_ssc_vals_ext;
            tap_data->hf_name = "scsi_ssc.opcode";
        break;
        case SCSI_DEV_CDROM:
            tap_data->prog = "MMC (cd/dvd)";
            tap_data->cdbnames_ext = &scsi_mmc_vals_ext;
            tap_data->hf_name = "scsi_mmc.opcode";
        break;
        case SCSI_DEV_SMC:
            tap_data->prog = "SMC (tape robot)";
            tap_data->cdbnames_ext = &scsi_smc_vals_ext;
            tap_data->hf_name = "scsi_smc.opcode";
        break;
        case SCSI_DEV_OSD:
            tap_data->prog = "OSD (object based)";
            tap_data->cdbnames_ext = &scsi_osd_vals_ext;
            tap_data->hf_name = "scsi_osd.opcode";
        break;
        }

        set_srt_table_param_data(srt, tap_data);
    }
    else
    {
        *err = g_strdup("<cmdset>[,<filter>]");
    }

    return pos;
}

/* TapeAlert page : read warning flag */
static void
log_parameter_2e_0001(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rw, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : write warning flag */
static void
log_parameter_2e_0002(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ww, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : hard error flag */
static void
log_parameter_2e_0003(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_he, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : media flag */
static void
log_parameter_2e_0004(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_media, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : read failure flag */
static void
log_parameter_2e_0005(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : write failure flag */
static void
log_parameter_2e_0006(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : media life flag */
static void
log_parameter_2e_0007(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ml, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : not data grade flag */
static void
log_parameter_2e_0008(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ndg, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : write protect flag */
static void
log_parameter_2e_0009(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wp, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : no removal flag */
static void
log_parameter_2e_000a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nr, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : cleaning media flag */
static void
log_parameter_2e_000b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cm, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : unsupported format flag */
static void
log_parameter_2e_000c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_uf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : removable mechanical cartridge failure flag */
static void
log_parameter_2e_000d(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rmcf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : unrecoverable mechanical cartridge failure flag */
static void
log_parameter_2e_000e(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_umcf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : memory chip in cartridge failure flag */
static void
log_parameter_2e_000f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_mcicf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : forced eject flag */
static void
log_parameter_2e_0010(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_fe, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : read only format flag */
static void
log_parameter_2e_0011(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rof, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : tape directory corrupted on load flag */
static void
log_parameter_2e_0012(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tdcol, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : nearing media life flag */
static void
log_parameter_2e_0013(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nml, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : clean now flag */
static void
log_parameter_2e_0014(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cn, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : clean periodic flag */
static void
log_parameter_2e_0015(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cp, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : expired cleaning media flag */
static void
log_parameter_2e_0016(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ecm, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : invalid cleaning tape flag */
static void
log_parameter_2e_0017(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ict, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : retention requested flag */
static void
log_parameter_2e_0018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rr, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : dual port interface error flag */
static void
log_parameter_2e_0019(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dpie, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : cooling fan failure flag */
static void
log_parameter_2e_001a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cff, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : power supply failure flag */
static void
log_parameter_2e_001b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_psf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : power consumption flag */
static void
log_parameter_2e_001c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_pc, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : drive maintenance flag */
static void
log_parameter_2e_001d(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dm, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : hardware a flag */
static void
log_parameter_2e_001e(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_hwa, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : hardware b flag */
static void
log_parameter_2e_001f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_hwb, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : interface flag */
static void
log_parameter_2e_0020(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_if, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : eject media flag */
static void
log_parameter_2e_0021(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_em, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : download failed flag */
static void
log_parameter_2e_0022(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dwf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : drive humidity flag */
static void
log_parameter_2e_0023(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drhu, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : drive temperature flag */
static void
log_parameter_2e_0024(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drtm, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : drive voltage flag */
static void
log_parameter_2e_0025(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drvo, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : periodic failure flag */
static void
log_parameter_2e_0026(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_pefa, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : diagnostics required flag */
static void
log_parameter_2e_0027(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dire, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : lost statistics flag */
static void
log_parameter_2e_0032(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_lost, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : tape directory invalid at unload flag */
static void
log_parameter_2e_0033(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tduau, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : tape system area write failure flag */
static void
log_parameter_2e_0034(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tsawf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : tape system area read failure flag */
static void
log_parameter_2e_0035(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tsarf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : no start of data flag */
static void
log_parameter_2e_0036(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nsod, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : loading failure flag */
static void
log_parameter_2e_0037(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_lofa, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : unrecoverable unload failure flag */
static void
log_parameter_2e_0038(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_uuf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : automatic interface failure flag */
static void
log_parameter_2e_0039(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_aif, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : firmware failure flag */
static void
log_parameter_2e_003a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_fwf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : worm medium integrity check failed flag */
static void
log_parameter_2e_003b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wmicf, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* TapeAlert page : worm medium overwrite attempted flag */
static void
log_parameter_2e_003c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wmoa, tvb, 0, 1, ENC_BIG_ENDIAN);
}


typedef void (*log_parameter_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef struct _log_page_parameters_t {
    guint32 number;
    const char *name;
    log_parameter_dissector dissector;
} log_page_parameters_t;
static const log_page_parameters_t tape_alert_log_parameters[] = {
    {0x0001,    "Read Warning", log_parameter_2e_0001},
    {0x0002,    "write warning", log_parameter_2e_0002},
    {0x0003,    "hard error", log_parameter_2e_0003},
    {0x0004,    "media", log_parameter_2e_0004},
    {0x0005,    "read failure", log_parameter_2e_0005},
    {0x0006,    "write failure", log_parameter_2e_0006},
    {0x0007,    "media life", log_parameter_2e_0007},
    {0x0008,    "not data grade", log_parameter_2e_0008},
    {0x0009,    "write protect", log_parameter_2e_0009},
    {0x000a,    "no removal", log_parameter_2e_000a},
    {0x000b,    "cleaning media", log_parameter_2e_000b},
    {0x000c,    "unsupported format", log_parameter_2e_000c},
    {0x000d,    "removable mechanical cartridge failure", log_parameter_2e_000d},
    {0x000e,    "unrecoverable mechanical cartridge failure", log_parameter_2e_000e},
    {0x000f,    "memory chip in cartridge failure", log_parameter_2e_000f},
    {0x0010,    "forced eject", log_parameter_2e_0010},
    {0x0011,    "read only format", log_parameter_2e_0011},
    {0x0012,    "tape directory corrupted on load", log_parameter_2e_0012},
    {0x0013,    "nearing media life", log_parameter_2e_0013},
    {0x0014,    "clean now", log_parameter_2e_0014},
    {0x0015,    "clean periodic", log_parameter_2e_0015},
    {0x0016,    "expired cleaning media", log_parameter_2e_0016},
    {0x0017,    "invalid cleaning tape", log_parameter_2e_0017},
    {0x0018,    "retention requested", log_parameter_2e_0018},
    {0x0019,    "dual port interface error", log_parameter_2e_0019},
    {0x001a,    "cooling fan failure", log_parameter_2e_001a},
    {0x001b,    "power supply failure", log_parameter_2e_001b},
    {0x001c,    "power consumption", log_parameter_2e_001c},
    {0x001d,    "drive maintenance", log_parameter_2e_001d},
    {0x001e,    "hardware a", log_parameter_2e_001e},
    {0x001f,    "hardware b", log_parameter_2e_001f},
    {0x0020,    "interface", log_parameter_2e_0020},
    {0x0021,    "eject media", log_parameter_2e_0021},
    {0x0022,    "download failed", log_parameter_2e_0022},
    {0x0023,    "drive humidity", log_parameter_2e_0023},
    {0x0024,    "drive temperature", log_parameter_2e_0024},
    {0x0025,    "drive voltage", log_parameter_2e_0025},
    {0x0026,    "periodic failure", log_parameter_2e_0026},
    {0x0027,    "diagnostics required", log_parameter_2e_0027},
    {0x0032,    "lost statistics", log_parameter_2e_0032},
    {0x0033,    "tape directory invalid at unload", log_parameter_2e_0033},
    {0x0034,    "tape system area write failure", log_parameter_2e_0034},
    {0x0035,    "tape system area read failure", log_parameter_2e_0035},
    {0x0036,    "no start of data", log_parameter_2e_0036},
    {0x0037,    "loading failure", log_parameter_2e_0037},
    {0x0038,    "unrecoverable unload failure", log_parameter_2e_0038},
    {0x0039,    "automatic interface failure", log_parameter_2e_0039},
    {0x003a,    "firmware failure", log_parameter_2e_003a},
    {0x003b,    "worm medium integrity check failed", log_parameter_2e_003b},
    {0x003c,    "worm medium overwrite attempted", log_parameter_2e_003c},
    {0, NULL, NULL}
};

typedef struct _log_pages_t {
    guint32 page;
    const log_page_parameters_t *parameters;
} log_pages_t;


#define LOG_PAGE_TAPE_ALERT     0x2e
static const value_string scsi_log_page_val[] = {
    {0x00, "Supported Log Pages"},
    {0x01, "Buffer Overrun/Underrun Page"},
    {0x02, "Error Counter (write) Page"},
    {0x03, "Error Counter (read) Page"},
    {0x04, "Error Counter (read reverse) Page"},
    {0x05, "Error Counter (verify) Page"},
    {0x06, "Non-medium Error Page"},
    {0x07, "Last n Error Events Page"},
    {0x08, "Format Status Log Page"},
    {0x0B, "Last n Deferred Errors or Async Events Page"},
    {0x0C, "Sequential-Access Device Log Page"},
    {0x0D, "Temperature Page"},
    {0x0E, "Start-Stop Cycle Counter Page"},
    {0x0F, "Application Client Page"},
    {0x10, "Self-test Results Page"},
    {0x11, "DTD Status Log Page"},
    {LOG_PAGE_TAPE_ALERT, "Tape-Alert Log Page (SSC)"},
    {0x2f, "Informational Exceptions Log Page"},
    {0, NULL},
};

static const log_pages_t log_pages[] = {
    {LOG_PAGE_TAPE_ALERT, tape_alert_log_parameters},
    {0, NULL}
};




static const value_string scsi_modesns_pc_val[] = {
    {0, "Current Values"},
    {1, "Changeable Values"},
    {2, "Default Values"},
    {3, "Saved Values"},
    {0, NULL},
};

#define SCSI_SPC_MODEPAGE_CTL      0x0A
#define SCSI_SPC_MODEPAGE_DISCON   0x02
#define SCSI_SCSI2_MODEPAGE_PERDEV  0x09  /* Obsolete in SPC-2; generic in SCSI-2 */
#define SCSI_SPC_MODEPAGE_INFOEXCP 0x1C
#define SCSI_SPC_MODEPAGE_PWR      0x1A
#define SCSI_SPC_MODEPAGE_LUN      0x18
#define SCSI_SPC_MODEPAGE_PORT     0x19
#define SCSI_SPC_MODEPAGE_VEND     0x00

static const value_string scsi_spc_modepage_val[] = {
    {SCSI_SPC_MODEPAGE_CTL,      "Control"},
    {SCSI_SPC_MODEPAGE_DISCON,   "Disconnect-Reconnect"},
    {SCSI_SCSI2_MODEPAGE_PERDEV, "Peripheral Device"},
    {SCSI_SPC_MODEPAGE_INFOEXCP, "Informational Exceptions Control"},
    {SCSI_SPC_MODEPAGE_PWR,      "Power Condition"},
    {SCSI_SPC_MODEPAGE_LUN,      "Protocol Specific LUN"},
    {SCSI_SPC_MODEPAGE_PORT,     "Protocol-Specific Port"},
    {SCSI_SPC_MODEPAGE_VEND,     "Vendor Specific Page"},
    {0x3F,                       "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_SBC_MODEPAGE_RDWRERR  0x01
#define SCSI_SBC_MODEPAGE_FMTDEV   0x03
#define SCSI_SBC_MODEPAGE_DISKGEOM 0x04
#define SCSI_SBC_MODEPAGE_FLEXDISK 0x05
#define SCSI_SBC_MODEPAGE_VERERR   0x07
#define SCSI_SBC_MODEPAGE_CACHE    0x08
#define SCSI_SBC_MODEPAGE_MEDTYPE  0x0B
#define SCSI_SBC_MODEPAGE_NOTPART  0x0C
#define SCSI_SBC_MODEPAGE_XORCTL   0x10

static const value_string scsi_sbc_modepage_val[] = {
    {SCSI_SBC_MODEPAGE_RDWRERR,  "Read/Write Error Recovery"},
    {SCSI_SBC_MODEPAGE_FMTDEV,   "Format Device"},
    {SCSI_SBC_MODEPAGE_DISKGEOM, "Rigid Disk Geometry"},
    {SCSI_SBC_MODEPAGE_FLEXDISK, "Flexible Disk"},
    {SCSI_SBC_MODEPAGE_VERERR,   "Verify Error Recovery"},
    {SCSI_SBC_MODEPAGE_CACHE,    "Caching"},
    {SCSI_SBC_MODEPAGE_MEDTYPE,  "Medium Types Supported"},
    {SCSI_SBC_MODEPAGE_NOTPART,  "Notch & Partition"},
    {SCSI_SBC_MODEPAGE_XORCTL,   "XOR Control"},
    {0x3F,                        "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_SSC2_MODEPAGE_DATACOMP 0x0F  /* data compression */
#define SCSI_SSC2_MODEPAGE_DEVCONF  0x10  /* device configuration */
#define SCSI_SSC2_MODEPAGE_MEDPAR1  0x11  /* medium partition (1) */
#define SCSI_SSC2_MODEPAGE_MEDPAR2  0x12  /* medium partition (2) */
#define SCSI_SSC2_MODEPAGE_MEDPAR3  0x13  /* medium partition (3) */
#define SCSI_SSC2_MODEPAGE_MEDPAR4  0x14  /* medium partition (4) */

static const value_string scsi_ssc2_modepage_val[] = {
    {SCSI_SSC2_MODEPAGE_DATACOMP, "Data Compression"},
    {SCSI_SSC2_MODEPAGE_DEVCONF,  "Device Configuration"},
    {SCSI_SSC2_MODEPAGE_MEDPAR1,  "Medium Partition (1)"},
    {SCSI_SSC2_MODEPAGE_MEDPAR2,  "Medium Partition (2)"},
    {SCSI_SSC2_MODEPAGE_MEDPAR3,  "Medium Partition (3)"},
    {SCSI_SSC2_MODEPAGE_MEDPAR4,  "Medium Partition (4)"},
    {0x3F,                        "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_SMC_MODEPAGE_EAA      0x1D  /* element address assignment */
#define SCSI_SMC_MODEPAGE_TRANGEOM 0x1E  /* transport geometry parameters */
#define SCSI_SMC_MODEPAGE_DEVCAP   0x1F  /* device capabilities */

static const value_string scsi_smc_modepage_val[] = {
    {SCSI_SMC_MODEPAGE_EAA,      "Element Address Assignment"},
    {SCSI_SMC_MODEPAGE_TRANGEOM, "Transport Geometry Parameters"},
    {SCSI_SMC_MODEPAGE_DEVCAP,   "Device Capabilities"},
    {0x3F,                        "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_MMC5_MODEPAGE_MRW     0x03  /* MRW */
#define SCSI_MMC5_MODEPAGE_WRPARAM 0x05  /* Write Parameters */
#define SCSI_MMC3_MODEPAGE_MMCAP   0x2A  /* device capabilities */

static const value_string scsi_mmc5_modepage_val[] = {
    {SCSI_MMC5_MODEPAGE_MRW,      "MRW"},
    {SCSI_MMC5_MODEPAGE_WRPARAM,  "Write Parameters"},
    {SCSI_MMC3_MODEPAGE_MMCAP,    "MM Capabilities and Mechanical Status"},
    {0x3F,                        "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_SPC_RESVIN_SVCA_RDKEYS 0
#define SCSI_SPC_RESVIN_SVCA_RDRESV 1
#define SCSI_SPC_RESVIN_SVCA_RPTCAP 2
#define SCSI_SPC_RESVIN_SVCA_FULL   3

static const value_string scsi_persresvin_svcaction_val[] = {
    {SCSI_SPC_RESVIN_SVCA_RDKEYS, "Read Keys"},
    {SCSI_SPC_RESVIN_SVCA_RDRESV, "Read Reservation"},
    {SCSI_SPC_RESVIN_SVCA_RPTCAP, "Report Capabilities"},
    {SCSI_SPC_RESVIN_SVCA_FULL,   "Read Full Status"},
    {0, NULL},
};

#define SCSI_PR_REGISTER 0
#define SCSI_PR_RESERVE 1
#define SCSI_PR_RELEASE 2
#define SCSI_PR_CLEAR 3
#define SCSI_PR_PREEMPT 4
#define SCSI_PR_PREEM_ABORT 5
#define SCSI_PR_REG_IGNORE 6
#define SCSI_PR_REG_MOVE 7
#define SCSI_PR_REPLACE_LOST 8

static const value_string scsi_persresvout_svcaction_val[] = {
    {SCSI_PR_REGISTER, "Register"},
    {SCSI_PR_RESERVE, "Reserve"},
    {SCSI_PR_RELEASE, "Release"},
    {SCSI_PR_CLEAR, "Clear"},
    {SCSI_PR_PREEMPT, "Preempt"},
    {SCSI_PR_PREEM_ABORT, "Preempt & Abort"},
    {SCSI_PR_REG_IGNORE, "Register & Ignore Existing Key"},
    {SCSI_PR_REG_MOVE, "Register & Move"},
    {SCSI_PR_REPLACE_LOST, "Replace Lost Reservation"},
    {0, NULL},
};

static const value_string scsi_persresv_scope_val[] = {
    {0, "LU Scope"},
    {1, "Obsolete"},
    {2, "Element Scope"},
    {0, NULL},
};

static const value_string scsi_persresv_type_val[] = {
    {1, "Write Excl"},
    {3, "Excl Access"},
    {5, "Write Excl, Registrants Only"},
    {6, "Excl Access, Registrants Only"},
    {7, "Write Excl, All Registrants"},
    {8, "Excl Access, All Registrants"},
    {0, NULL},
};

static const value_string scsi_qualifier_val[] = {
    {0x0, "Device type is connected to logical unit"},
    {0x1, "Device type is supported by server but is not connected to logical unit"},
    {0x3, "Device type is not supported by server"},
    { 0, NULL }
};

static const value_string scsi_devtype_val[] = {
    {SCSI_DEV_SBC   , "Direct Access Device"},
    {SCSI_DEV_SSC   , "Sequential Access Device"},
    {SCSI_DEV_PRNT  , "Printer"},
    {SCSI_DEV_PROC  , "Processor"},
    {SCSI_DEV_WORM  , "WORM"},
    {SCSI_DEV_CDROM , "CD-ROM"},
    {SCSI_DEV_SCAN  , "Scanner"},
    {SCSI_DEV_OPTMEM, "Optical Memory"},
    {SCSI_DEV_SMC   , "Medium Changer"},
    {SCSI_DEV_COMM  , "Communication"},
    {SCSI_DEV_RAID  , "Storage Array"},
    {SCSI_DEV_SES   , "Enclosure Services"},
    {SCSI_DEV_RBC   , "Simplified Block Device"},
    {SCSI_DEV_OCRW  , "Optical Card Reader/Writer"},
    {SCSI_DEV_OSD   , "Object-based Storage Device"},
    {SCSI_DEV_ADC   , "Automation/Drive Interface"},
    {0x1E           , "Well known logical unit"},
    {SCSI_DEV_NOLUN , "Unknown or no device type"},
    {0, NULL},
};

static const enum_val_t scsi_devtype_options[] = {
    {"block",         "Block Device",                SCSI_DEV_SBC},
    {"sequential",    "Sequential Device",           SCSI_DEV_SSC},
    {"objectbased",   "Object Based Storage Device", SCSI_DEV_OSD},
    {"mediumchanger", "Medium Changer Device",       SCSI_DEV_SMC},
    {"cdrom",         "Multimedia Device",           SCSI_DEV_CDROM},
    {NULL, NULL, -1},
};

static const value_string scsi_inquiry_vers_val[] = {
    {0x00, "No Compliance to any Standard"},
    {0x02, "Compliance to ANSI X3.131:1994"},
    {0x03, "Compliance to ANSI X3.301:1997"},
    {0x04, "Compliance to SPC-2"},
    {0x05, "Compliance to SPC-3"},
    {0x06, "Compliance to SPC-4"},
    {0x80, "Compliance to ISO/IEC 9316:1995"},
    {0x82, "Compliance to ISO/IEC 9316:1995 and to ANSI X3.131:1994"},
    {0x83, "Compliance to ISO/IEC 9316:1995 and to ANSI X3.301:1997"},
    {0x84, "Compliance to ISO/IEC 9316:1995 and SPC-2"},
    {0, NULL},
};

static const value_string scsi_modesense_medtype_sbc_val[] = {
    {0x00, "Default"},
    {0x01, "Flexible disk, single-sided; unspecified medium"},
    {0x02, "Flexible disk, double-sided; unspecified medium"},
    {0x05, "Flexible disk, single-sided, single density; 200mm/8in diameter"},
    {0x06, "Flexible disk, double-sided, single density; 200mm/8in diameter"},
    {0x09, "Flexible disk, single-sided, double density; 200mm/8in diameter"},
    {0x0A, "Flexible disk, double-sided, double density; 200mm/8in diameter"},
    {0x0D, "Flexible disk, single-sided, single density; 130mm/5.25in diameter"},
    {0x12, "Flexible disk, double-sided, single density; 130mm/5.25in diameter"},
    {0x16, "Flexible disk, single-sided, double density; 130mm/5.25in diameter"},
    {0x1A, "Flexible disk, double-sided, double density; 130mm/5.25in diameter"},
    {0x1E, "Flexible disk, double-sided; 90mm/3.5in diameter"},
    {0x40, "Direct-access magnetic tape, 12 tracks"},
    {0x44, "Direct-access magnetic tape, 24 tracks"},
    {0, NULL},
};

static const value_string scsi_verdesc_val[] = {
    {0x0000, "Version Descriptor Not Supported or No Standard Identified"},
    {0x0020, "SAM (no version claimed)"},
    {0x003B, "SAM T10/0994-D revision 18"},
    {0x003C, "SAM ANSI INCITS 270-1996"},
    {0x0040, "SAM-2 (no version claimed)"},
    {0x0054, "SAM-2 T10/1157-D revision 23"},
    {0x0055, "SAM-2 T10/1157-D revision 24"},
    {0x005C, "SAM-2 ANSI INCITS 366-2003"},
    {0x005E, "SAM-2 ISO/IEC 14776-412"},
    {0x0060, "SAM-3 (no version claimed)"},
    {0x0062, "SAM-3 T10/1561-D revision 7"},
    {0x0075, "SAM-3 T10/1561-D revision 13"},
    {0x0076, "SAM-3 T10/1561-D revision 14"},
    {0x0077, "SAM-3 ANSI INCITS 402-2005"},
    {0x0080, "SAM-4 (no version claimed)"},
    {0x0087, "SAM-4 T10/1683-D revision 13"},
    {0x008B, "SAM-4 T10/1683-D revision 14"},
    {0x0090, "SAM-4 ANSI INCITS 447-2008"},
    {0x0092, "SAM-4 ISO/IEC 14776-414"},
    {0x00A0, "SAM-5 (no version claimed)"},
    {0x00A2, "SAM-5 T10/2104-D revision 4"},
    {0x0120, "SPC (no version claimed)"},
    {0x013B, "SPC T10/0995-D revision 11a"},
    {0x013C, "SPC ANSI INCITS 301-1997"},
    {0x0140, "MMC (no version claimed)"},
    {0x015B, "MMC T10/1048-D revision 10a"},
    {0x015C, "MMC ANSI INCITS 304-1997"},
    {0x0160, "SCC (no version claimed)"},
    {0x017B, "SCC T10/1047-D revision 06c"},
    {0x017C, "SCC ANSI INCITS 276-1997"},
    {0x0180, "SBC (no version claimed)"},
    {0x019B, "SBC T10/0996-D revision 08c"},
    {0x019C, "SBC ANSI INCITS 306-1998"},
    {0x01A0, "SMC (no version claimed)"},
    {0x01BB, "SMC T10/0999-D revision 10a"},
    {0x01BC, "SMC ANSI INCITS 314-1998"},
    {0x01BE, "SMC ISO/IEC 14776-351"},
    {0x01C0, "SES (no version claimed)"},
    {0x01DB, "SES T10/1212-D revision 08b"},
    {0x01DC, "SES ANSI INCITS 305-1998"},
    {0x01DD, "SES T10/1212 revision 08b w/ Amendment ANSI INCITS.305/AM1-2000"},
    {0x01DE, "SES ANSI INCITS 305-1998 w/ Amendment ANSI INCITS.305/AM1-2000"},
    {0x01E0, "SCC-2 (no version claimed)"},
    {0x01FB, "SCC-2 T10/1125-D revision 4"},
    {0x01FC, "SCC-2 ANSI INCITS 318-1998"},
    {0x0200, "SSC (no version claimed)"},
    {0x0201, "SSC T10/0997-D revision 17"},
    {0x0207, "SSC T10/0997-D revision 22"},
    {0x021C, "SSC ANSI INCITS 335-2000"},
    {0x0220, "RBC (no version claimed)"},
    {0x0238, "RBC T10/1240-D revision 10a"},
    {0x023C, "RBC ANSI INCITS 330-2000"},
    {0x0240, "MMC-2 (no version claimed)"},
    {0x0255, "MMC-2 T10/1228-D revision 11"},
    {0x025B, "MMC-2 T10/1228-D revision 11a"},
    {0x025C, "MMC-2 ANSI INCITS 333-2000"},
    {0x0260, "SPC-2 (no version claimed)"},
    {0x0267, "SPC-2 T10/1236-D revision 12"},
    {0x0269, "SPC-2 T10/1236-D revision 18"},
    {0x0275, "SPC-2 T10/1236-D revision 19"},
    {0x0276, "SPC-2 T10/1236-D revision 20"},
    {0x0277, "SPC-2 ANSI INCITS 351-2001"},
    {0x0278, "SPC-2 ISO/IEC 14776-452"},
    {0x0280, "OCRW (no version claimed)"},
    {0x029E, "OCRW ISO/IEC 14776-381"},
    {0x02A0, "MMC-3 (no version claimed)"},
    {0x02B5, "MMC-3 T10/1363-D revision 9"},
    {0x02B6, "MMC-3 T10/1363-D revision 10g"},
    {0x02B8, "MMC-3 ANSI INCITS 360-2002"},
    {0x02E0, "SMC-2 (no version claimed)"},
    {0x02F5, "SMC-2 T10/1383-D revision 5"},
    {0x02FC, "SMC-2 T10/1383-D revision 6"},
    {0x02FD, "SMC-2 T10/1383-D revision 7"},
    {0x02FE, "SMC-2 ANSI INCITS 382-2004"},
    {0x0300, "SPC-3 (no version claimed)"},
    {0x0301, "SPC-3 T10/1416-D revision 7"},
    {0x0307, "SPC-3 T10/1416-D revision 21"},
    {0x030F, "SPC-3 T10/1416-D revision 22"},
    {0x0312, "SPC-3 T10/1416-D revision 23"},
    {0x0314, "SPC-3 ANSI INCITS 408-2005"},
    {0x0316, "SPC-3 ISO/IEC 14776-453"},
    {0x0320, "SBC-2 (no version claimed)"},
    {0x0322, "SBC-2 T10/1417-D revision 5a"},
    {0x0324, "SBC-2 T10/1417-D revision 15"},
    {0x033B, "SBC-2 T10/1417-D revision 16"},
    {0x033D, "SBC-2 ANSI INCITS 405-2005"},
    {0x033E, "SBC-2 ISO/IEC 14776-322"},
    {0x0340, "OSD (no version claimed)"},
    {0x0341, "OSD T10/1355-D revision 0"},
    {0x0342, "OSD T10/1355-D revision 7a"},
    {0x0343, "OSD T10/1355-D revision 8"},
    {0x0344, "OSD T10/1355-D revision 9"},
    {0x0355, "OSD T10/1355-D revision 10"},
    {0x0356, "OSD ANSI INCITS 400-2004"},
    {0x0360, "SSC-2 (no version claimed)"},
    {0x0374, "SSC-2 T10/1434-D revision 7"},
    {0x0375, "SSC-2 T10/1434-D revision 9"},
    {0x037D, "SSC-2 ANSI INCITS 380-2003"},
    {0x0380, "BCC (no version claimed)"},
    {0x03A0, "MMC-4 (no version claimed)"},
    {0x03B0, "MMC-4 T10/1545-D revision 5"},
    {0x03B1, "MMC-4 T10/1545-D revision 5a"},
    {0x03BD, "MMC-4 T10/1545-D revision 3"},
    {0x03BE, "MMC-4 T10/1545-D revision 3d"},
    {0x03BF, "MMC-4 ANSI INCITS 401-2005"},
    {0x03C0, "ADC (no version claimed)"},
    {0x03D5, "ADC T10/1558-D revision 6"},
    {0x03D6, "ADC T10/1558-D revision 7"},
    {0x03D7, "ADC ANSI INCITS 403-2005"},
    {0x03E0, "SES-2 (no version claimed)"},
    {0x03E1, "SES-2 T10/1559-D revision 16"},
    {0x03E7, "SES-2 T10/1559-D revision 19"},
    {0x03EB, "SES-2 T10/1559-D revision 20"},
    {0x03F0, "SES-2 ANSI INCITS 448-2008"},
    {0x03F2, "SES-2 ISO/IEC 14776-372"},
    {0x0400, "SSC-3 (no version claimed)"},
    {0x0403, "SSC-3 T10/1611-D revision 04a"},
    {0x0407, "SSC-3 T10/1611-D revision 5"},
    {0x0409, "SSC-3 ANSI INCITS 467-2011"},
    {0x0420, "MMC-5 (no version claimed)"},
    {0x042F, "MMC-5 T10/1675-D revision 3"},
    {0x0431, "MMC-5 T10/1675-D revision 03b"},
    {0x0432, "MMC-5 T10/1675-D revision 4"},
    {0x0434, "MMC-5 ANSI INCITS 430-2007"},
    {0x0440, "OSD-2 (no version claimed)"},
    {0x0444, "OSD-2 T10/1729-D revision 4"},
    {0x0446, "OSD-2 T10/1729-D revision 5"},
    {0x0448, "OSD-2 ANSI INCITS 458-2011"},
    {0x0460, "SPC-4 (no version claimed)"},
    {0x0461, "SPC-4 T10/BSR INCITS 513 revision 16"},
    {0x0462, "SPC-4 T10/BSR INCITS 513 revision 18"},
    {0x0463, "SPC-4 T10/BSR INCITS 513 revision 23"},
    {0x0466, "SPC-4 T10/BSR INCITS 513 revision 36"},
    {0x0480, "SMC-3 (no version claimed)"},
    {0x0482, "SMC-3 T10/1730-D revision 15"},
    {0x0484, "SMC-3 T10/1730-D revision 16"},
    {0x0486, "SMC-3 ANSI INCITS 484-2012"},
    {0x04A0, "ADC-2 (no version claimed)"},
    {0x04A7, "ADC-2 T10/1741-D revision 7"},
    {0x04AA, "ADC-2 T10/1741-D revision 8"},
    {0x04AC, "ADC-2 ANSI INCITS 441-2008"},
    {0x04C0, "SBC-3 (no version claimed)"},
    {0x04C3, "SBC-3 T10/BSR INCITS 514 revision 35"},
    {0x04E0, "MMC-6 (no version claimed)"},
    {0x04E3, "MMC-6 T10/1836-D revision 02b"},
    {0x04E5, "MMC-6 T10/1836-D revision 02g"},
    {0x04E6, "MMC-6 ANSI INCITS 468-2010"},
    {0x04E7, "MMC-6 ANSI INCITS 468-2010 + MMC-6/AM1 ANSI"},
    {0x0500, "ADC-3 (no version claimed)"},
    {0x0502, "ADC-3 T10/1895-D revision 4"},
    {0x0504, "ADC-3 T10/1895-D revision 5"},
    {0x0506, "ADC-3 T10/1895-D revision 05a"},
    {0x050A, "ADC-3 ANSI INCITS 497-2012"},
    {0x0520, "SSC-4 (no version claimed)"},
    {0x0523, "SSC-4 T10/BSR INCITS 516 revision 2"},
    {0x0560, "OSD-3 (no version claimed)"},
    {0x0580, "SES-3 (no version claimed)"},
    {0x05A0, "SSC-5 (no version claimed)"},
    {0x05C0, "SPC-5 (no version claimed)"},
    {0x05E0, "SFSC (no version claimed)"},
    {0x0600, "SBC-4 (no version claimed)"},
    {0x0820, "SSA-TL2 (no version claimed)"},
    {0x083B, "SSA-TL2 T10.1/1147-D revision 05b"},
    {0x083C, "SSA-TL2 ANSI INCITS 308-1998"},
    {0x0840, "SSA-TL1 (no version claimed)"},
    {0x085B, "SSA-TL1 T10.1/0989-D revision 10b"},
    {0x085C, "SSA-TL1 ANSI INCITS 295-1996"},
    {0x0860, "SSA-S3P (no version claimed)"},
    {0x087B, "SSA-S3P T10.1/1051-D revision 05b"},
    {0x087C, "SSA-S3P ANSI INCITS 309-1998"},
    {0x0880, "SSA-S2P (no version claimed)"},
    {0x089B, "SSA-S2P T10.1/1121-D revision 07b"},
    {0x089C, "SSA-S2P ANSI INCITS 294-1996"},
    {0x08A0, "SIP (no version claimed)"},
    {0x08BB, "SIP T10/0856-D revision 10"},
    {0x08BC, "SIP ANSI INCITS 292-1997"},
    {0x08C0, "FCP (no version claimed)"},
    {0x08DB, "FCP T10/0993-D revision 12"},
    {0x08DC, "FCP ANSI INCITS 269-1996"},
    {0x08E0, "SBP-2 (no version claimed)"},
    {0x08FB, "SBP-2 T10/1155-D revision 4"},
    {0x08FC, "SBP-2 ANSI INCITS 325-1998"},
    {0x0900, "FCP-2 (no version claimed)"},
    {0x0901, "FCP-2 T10/1144-D revision 4"},
    {0x0915, "FCP-2 T10/1144-D revision 7"},
    {0x0916, "FCP-2 T10/1144-D revision 7a"},
    {0x0917, "FCP-2 ANSI INCITS 350-2003"},
    {0x0918, "FCP-2 T10/1144-D revision 8"},
    {0x0920, "SST (no version claimed)"},
    {0x0935, "SST T10/1380-D revision 8b"},
    {0x0940, "SRP (no version claimed)"},
    {0x0954, "SRP T10/1415-D revision 10"},
    {0x0955, "SRP T10/1415-D revision 16a"},
    {0x095C, "SRP ANSI INCITS 365-2002"},
    {0x0960, "iSCSI (no version claimed)"},
    {0x0980, "SBP-3 (no version claimed)"},
    {0x0982, "SBP-3 T10/1467-D revision 1f"},
    {0x0994, "SBP-3 T10/1467-D revision 3"},
    {0x099A, "SBP-3 T10/1467-D revision 4"},
    {0x099B, "SBP-3 T10/1467-D revision 5"},
    {0x099C, "SBP-3 ANSI INCITS 375-2004"},
    {0x09C0, "ADP (no version claimed)"},
    {0x09E0, "ADT (no version claimed)"},
    {0x09F9, "ADT T10/1557-D revision 11"},
    {0x09FA, "ADT T10/1557-D revision 14"},
    {0x09FD, "ADT ANSI INCITS 406-2005"},
    {0x0A00, "FCP-3 (no version claimed)"},
    {0x0A07, "FCP-3 T10/1560-D revision 3f"},
    {0x0A0F, "FCP-3 T10/1560-D revision 4"},
    {0x0A11, "FCP-3 ANSI INCITS 416-2006"},
    {0x0A1C, "FCP-3 ISO/IEC 14776-223"},
    {0x0A20, "ADT-2 (no version claimed)"},
    {0x0A22, "ADT-2 T10/1742-D revision 6"},
    {0x0A27, "ADT-2 T10/1742-D revision 8"},
    {0x0A28, "ADT-2 T10/1742-D revision 9"},
    {0x0A2B, "ADT-2 ANSI INCITS 472-2011"},
    {0x0A40, "FCP-4 (no version claimed)"},
    {0x0A42, "FCP-4 T10/1828-D revision 1"},
    {0x0A44, "FCP-4 T10/1828-D revision 2"},
    {0x0A45, "FCP-4 T10/1828-D revision 02b"},
    {0x0A46, "FCP-4 ANSI INCITS 481-2012"},
    {0x0AA0, "SPI (no version claimed)"},
    {0x0AB9, "SPI T10/0855-D revision 15a"},
    {0x0ABA, "SPI ANSI INCITS 253-1995"},
    {0x0ABB, "SPI T10/0855-D revision 15a with SPI Amnd revision 3a"},
    {0x0ABC, "SPI ANSI INCITS 253-1995 with SPI Amnd ANSI INCITS 253/AM1-1998"},
    {0x0AC0, "Fast-20 (no version claimed)"},
    {0x0ADB, "Fast-20 T10/1071 revision 6"},
    {0x0ADC, "Fast-20 ANSI INCITS 277-1996"},
    {0x0AE0, "SPI-2 (no version claimed)"},
    {0x0AFB, "SPI-2 T10/1142-D revision 20b"},
    {0x0AFC, "SPI-2 ANSI INCITS 302-1999"},
    {0x0B00, "SPI-3 (no version claimed)"},
    {0x0B18, "SPI-3 T10/1302-D revision 10"},
    {0x0B19, "SPI-3 T10/1302-D revision 13a"},
    {0x0B1A, "SPI-3 T10/1302-D revision 14"},
    {0x0B1C, "SPI-3 ANSI INCITS 336-2000"},
    {0x0B20, "EPI (no version claimed)"},
    {0x0B3B, "EPI T10/1134 revision 16"},
    {0x0B3C, "EPI ANSI INCITS TR-23 1999"},
    {0x0B40, "SPI-4 (no version claimed)"},
    {0x0B54, "SPI-4 T10/1365-D revision 7"},
    {0x0B55, "SPI-4 T10/1365-D revision 9"},
    {0x0B56, "SPI-4 ANSI INCITS 362-2002"},
    {0x0B59, "SPI-4 T10/1365-D revision 10"},
    {0x0B60, "SPI-5 (no version claimed)"},
    {0x0B79, "SPI-5 T10/1525-D revision 3"},
    {0x0B7A, "SPI-5 T10/1525-D revision 5"},
    {0x0B7B, "SPI-5 T10/1525-D revision 6"},
    {0x0B7C, "SPI-5 ANSI INCITS 367-2003"},
    {0x0BE0, "SAS (no version claimed)"},
    {0x0BE1, "SAS T10/1562-D revision 1"},
    {0x0BF5, "SAS T10/1562-D revision 3"},
    {0x0BFA, "SAS T10/1562-D revision 4"},
    {0x0BFB, "SAS T10/1562-D revision 4"},
    {0x0BFC, "SAS T10/1562-D revision 5"},
    {0x0BFD, "SAS ANSI INCITS 376-2003"},
    {0x0C00, "SAS-1.1 (no version claimed)"},
    {0x0C07, "SAS-1.1 T10/1601-D revision 9"},
    {0x0C0F, "SAS-1.1 T10/1601-D revision 10"},
    {0x0C11, "SAS-1.1 ANSI INCITS 417-2006"},
    {0x0C12, "SAS-1.1 ISO/IEC 14776-151"},
    {0x0C20, "SAS-2 (no version claimed)"},
    {0x0C23, "SAS-2 T10/1760-D revision 14"},
    {0x0C27, "SAS-2 T10/1760-D revision 15"},
    {0x0C28, "SAS-2 T10/1760-D revision 16"},
    {0x0C2A, "SAS-2 ANSI INCITS 457-2010"},
    {0x0C40, "SAS-2.1 (no version claimed)"},
    {0x0C48, "SAS-2.1 T10/2125-D revision 4"},
    {0x0C4A, "SAS-2.1 T10/2125-D revision 6"},
    {0x0C4B, "SAS-2.1 T10/2125-D revision 7"},
    {0x0C4E, "SAS-2.1 ANSI INCITS 478-2011"},
    {0x0C60, "SAS-3 (no version claimed)"},
    {0x0C63, "SAS-3 T10/BSR INCITS 519 revision 05a"},
    {0x0D20, "FC-PH (no version claimed)"},
    {0x0D3B, "FC-PH ANSI INCITS 230-1994"},
    {0x0D3C, "FC-PH ANSI INCITS 230-1994 with Amnd 1 ANSI INCITS 230/AM1-1996"},
    {0x0D40, "FC-AL (no version claimed)"},
    {0x0D5C, "FC-AL ANSI INCITS 272-1996"},
    {0x0D60, "FC-AL-2 (no version claimed)"},
    {0x0D61, "FC-AL-2 T11/1133-D revision 7.0"},
    {0x0D63, "FC-AL-2 ANSI INCITS 332-1999 with AM1-2003 & AM2-2006"},
    {0x0D64, "FC-AL-2 ANSI INCITS 332-1999 with Amnd 2 AM2-2006"},
    {0x0D65, "FC-AL-2 ISO/IEC 14165-122 with AM1 & AM2"},
    {0x0D7C, "FC-AL-2 ANSI INCITS 332-1999"},
    {0x0D7D, "FC-AL-2 ANSI INCITS 332-1999 with Amnd 1 AM1-2003"},
    {0x0D80, "FC-PH-3 (no version claimed)"},
    {0x0D9C, "FC-PH-3 ANSI INCITS 303-1998"},
    {0x0DA0, "FC-FS (no version claimed)"},
    {0x0DB7, "FC-FS T11/1331-D revision 1.2"},
    {0x0DB8, "FC-FS T11/1331-D revision 1.7"},
    {0x0DBC, "FC-FS ANSI INCITS 373-2003"},
    {0x0DBD, "FC-FS ISO/IEC 14165-251"},
    {0x0DC0, "FC-PI (no version claimed)"},
    {0x0DDC, "FC-PI ANSI INCITS 352-2002"},
    {0x0DE0, "FC-PI-2 (no version claimed)"},
    {0x0DE2, "FC-PI-2 T11/1506-D revision 5.0"},
    {0x0DE4, "FC-PI-2 ANSI INCITS 404-2006"},
    {0x0E00, "FC-FS-2 (no version claimed)"},
    {0x0E02, "FC-FS-2 ANSI INCITS 242-2007"},
    {0x0E03, "FC-FS-2 ANSI INCITS 242-2007 with AM1 ANSI INCITS 242/AM1-2007"},
    {0x0E20, "FC-LS (no version claimed)"},
    {0x0E21, "FC-LS T11/1620-D revision 1.62"},
    {0x0E29, "FC-LS ANSI INCITS 433-2007"},
    {0x0E40, "FC-SP (no version claimed)"},
    {0x0E42, "FC-SP T11/1570-D revision 1.6"},
    {0x0E45, "FC-SP ANSI INCITS 426-2007"},
    {0x0E60, "FC-PI-3 (no version claimed)"},
    {0x0E62, "FC-PI-3 T11/1625-D revision 2.0"},
    {0x0E68, "FC-PI-3 T11/1625-D revision 2.1"},
    {0x0E6A, "FC-PI-3 T11/1625-D revision 4.0"},
    {0x0E6E, "FC-PI-3 ANSI INCITS 460-2011"},
    {0x0E80, "FC-PI-4 (no version claimed)"},
    {0x0E82, "FC-PI-4 T11/1647-D revision 8.0"},
    {0x0E88, "FC-PI-4 ANSI INCITS 450-2009"},
    {0x0EA0, "FC 10GFC (no version claimed)"},
    {0x0EA2, "FC 10GFC ANSI INCITS 364-2003"},
    {0x0EA3, "FC 10GFC ISO/IEC 14165-116"},
    {0x0EA5, "FC 10GFC ISO/IEC 14165-116 with AM1"},
    {0x0EA6, "FC 10GFC ANSI INCITS 364-2003 with AM1 ANSI INCITS 364/AM1-2007"},
    {0x0EC0, "FC-SP-2 (no version claimed)"},
    {0x0EE0, "FC-FS-3 (no version claimed)"},
    {0x0EE2, "FC-FS-3 T11/1861-D revision 0.9"},
    {0x0EE7, "FC-FS-3 T11/1861-D revision 1.0"},
    {0x0EE9, "FC-FS-3 T11/1861-D revision 1.10"},
    {0x0EEB, "FC-FS-3 ANSI INCITS 470-2011"},
    {0x0F00, "FC-LS-2 (no version claimed)"},
    {0x0F03, "FC-LS-2 T11/2103-D revision 2.11"},
    {0x0F05, "FC-LS-2 T11/2103-D revision 2.21"},
    {0x0F07, "FC-LS-2 ANSI INCITS 477-2011"},
    {0x0F20, "FC-PI-5 (no version claimed)"},
    {0x0F27, "FC-PI-5 T11/2118-D revision 2.00"},
    {0x0F28, "FC-PI-5 T11/2118-D revision 3.00"},
    {0x0F2A, "FC-PI-5 T11/2118-D revision 6.00"},
    {0x0F2B, "FC-PI-5 T11/2118-D revision 6.10"},
    {0x0F2E, "FC-PI-5 ANSI INCITS 479-2011"},
    {0x0F40, "FC-PI-6 (no version claimed)"},
    {0x0F60, "FC-FS-4 (no version claimed)"},
    {0x0F80, "FC-LS-3 (no version claimed)"},
    {0x12A0, "FC-SCM (no version claimed)"},
    {0x12A3, "FC-SCM T11/1824DT revision 1.0"},
    {0x12A5, "FC-SCM T11/1824DT revision 1.1"},
    {0x12A7, "FC-SCM T11/1824DT revision 1.4"},
    {0x12AA, "FC-SCM INCITS TR-47 2012"},
    {0x12C0, "FC-DA-2 (no version claimed)"},
    {0x12C3, "FC-DA-2 T11/1870DT revision 1.04"},
    {0x12C5, "FC-DA-2 T11/1870DT revision 1.06"},
    {0x12C9, "FC-DA-2 INCITS TR-49 2012"},
    {0x12E0, "FC-DA (no version claimed)"},
    {0x12E2, "FC-DA T11/1513-DT revision 3.1"},
    {0x12E8, "FC-DA ANSI INCITS TR-36 2004"},
    {0x12E9, "FC-DA ISO/IEC 14165-341"},
    {0x1300, "FC-Tape (no version claimed)"},
    {0x1301, "FC-Tape T11/1315 revision 1.16"},
    {0x131B, "FC-Tape T11/1315 revision 1.17"},
    {0x131C, "FC-Tape ANSI INCITS TR-24 1999"},
    {0x1320, "FC-FLA (no version claimed)"},
    {0x133B, "FC-FLA T11/1235 revision 7"},
    {0x133C, "FC-FLA ANSI INCITS TR-20 1998"},
    {0x1340, "FC-PLDA (no version claimed)"},
    {0x135B, "FC-PLDA T11/1162 revision 2.1"},
    {0x135C, "FC-PLDA ANSI INCITS TR-19 1998"},
    {0x1360, "SSA-PH2 (no version claimed)"},
    {0x137B, "SSA-PH2 T10.1/1145-D revision 09c"},
    {0x137C, "SSA-PH2 ANSI INCITS 293-1996"},
    {0x1380, "SSA-PH3 (no version claimed)"},
    {0x139B, "SSA-PH3 T10.1/1146-D revision 05b"},
    {0x139C, "SSA-PH3 ANSI INCITS 307-1998"},
    {0x14A0, "IEEE 1394 (no version claimed)"},
    {0x14BD, "ANSI IEEE 1394-1995"},
    {0x14C0, "IEEE 1394a (no version claimed)"},
    {0x14E0, "IEEE 1394b (no version claimed)"},
    {0x15E0, "ATA/ATAPI-6 (no version claimed)"},
    {0x15FD, "ATA/ATAPI-6 ANSI INCITS 361-2002"},
    {0x1600, "ATA/ATAPI-7 (no version claimed)"},
    {0x1602, "ATA/ATAPI-7 T13/1532-D revision 3"},
    {0x161C, "ATA/ATAPI-7 ANSI INCITS 397-2005"},
    {0x161E, "ATA/ATAPI-7 ISO/IEC 24739"},
    {0x1620, "ATA/ATAPI-8 ATA8-AAM (no version claimed)"},
    {0x1621, "ATA/ATAPI-8 ATA8-APT Parallel Transport (no version claimed)"},
    {0x1622, "ATA/ATAPI-8 ATA8-AST Serial Transport (no version claimed)"},
    {0x1623, "ATA/ATAPI-8 ATA8-ACS ATA/ATAPI Command Set (no version claimed)"},
    {0x1628, "ATA/ATAPI-8 ATA8-AAM ANSI INCITS 451-2008"},
    {0x162A, "ATA/ATAPI-8 ATA8-ACS ANSI INCITS 452-2009 w/Amendment 1"},
    {0x1728, "Universal Serial Bus Specification, Revision 1.1"},
    {0x1729, "Universal Serial Bus Specification, Revision 2.0"},
    {0x1730, "USB Mass Storage Class Bulk-Only Transport, Revision 1.0"},
    {0x1740, "UAS (no version claimed)"},
    {0x1743, "UAS T10/2095-D revision 2"},
    {0x1747, "UAS T10/2095-D revision 4"},
    {0x1748, "UAS ANSI INCITS 471-2010"},
    {0x1761, "ACS-2 (no version claimed)"},
    {0x1762, "ACS-2 ANSI INCITS 482-2013"},
    {0x1765, "ACS-3 (no version claimed)"},
    {0x1780, "UAS-2 (no version claimed)"},
    {0x1EA0, "SAT (no version claimed)"},
    {0x1EA7, "SAT T10/1711-D revision 8"},
    {0x1EAB, "SAT T10/1711-D revision 9"},
    {0x1EAD, "SAT ANSI INCITS 431-2007"},
    {0x1EC0, "SAT-2 (no version claimed)"},
    {0x1EC4, "SAT-2 T10/1826-D revision 6"},
    {0x1EC8, "SAT-2 T10/1826-D revision 9"},
    {0x1ECA, "SAT-2 ANSI INCITS 465-2010"},
    {0x1EE0, "SAT-3 (no version claimed)"},
    {0x1EE2, "SAT-3 T10/BSR INCITS 517 revision 4"},
    {0x1F00, "SAT-4 (no version claimed)"},
    {0x20A0, "SPL (no version claimed)"},
    {0x20A3, "SPL T10/2124-D revision 6a"},
    {0x20A5, "SPL T10/2124-D revision 7"},
    {0x20A7, "SPL ANSI INCITS 476-2011"},
    {0x20A8, "SPL ANSI INCITS 476-2011 + SPL AM1 INCITS 476/AM1 2012"},
    {0x20C0, "SPL-2 (no version claimed)"},
    {0x20C2, "SPL-2 T10/BSR INCITS 505 revision 4"},
    {0x20C4, "SPL-2 T10/BSR INCITS 505 revision 5"},
    {0x20E0, "SPL-3 (no version claimed)"},
    {0x21E0, "SOP (no version claimed)"},
    {0x21E4, "SOP T10/BSR INCITS 489 revision 4"},
    {0x2200, "PQI (no version claimed)"},
    {0x2204, "PQI T10/BSR INCITS 490 revision 6"},
    {0x2220, "SOP-2 (no version claimed)"},
    {0x2240, "PQI-2 (no version claimed)"},
    {0xFFC0, "IEEE 1667 (no version claimed)"},
    {0xFFC1, "IEEE 1667-2006"},
    {0xFFC2, "IEEE 1667-2009"},
    {0, NULL},
};

static value_string_ext scsi_verdesc_val_ext = VALUE_STRING_EXT_INIT(scsi_verdesc_val);

/* Command Support Data "Support" field definitions */
static const value_string scsi_cmdt_supp_val[] = {
    {0, "Data not currently available"},
    {1, "SCSI Command not supported"},
    {2, "Reserved"},
    {3, "SCSI Command supported in conformance with a SCSI standard"},
    {4, "Vendor Specific"},
    {5, "SCSI Command supported in a vendor specific manner"},
    {6, "Vendor Specific"},
    {7, "Reserved"},
    {0, NULL},
};

#define CODESET_BINARY  1
#define CODESET_ASCII   2
#define CODESET_UTF8    3

const value_string scsi_devid_codeset_val[] = {
    {0,              "Reserved"},
    {CODESET_BINARY, "Identifier field contains binary values"},
    {CODESET_ASCII,  "Identifier field contains ASCII graphic codes"},
    {CODESET_UTF8,   "Identifier field contains UTF-8 codes"},
    {0,              NULL},
};

static const value_string scsi_devid_assoc_val[] = {
    {0, "Identifier is associated with addressed logical/physical device"},
    {1, "Identifier is associated with the port that received the request"},
    {2, "Identifier is associated with the SCSI target devices that contains the logical/physical device"},
    {0, NULL},
};

#define DEVID_TYPE_VEND_ID_VEND_SPEC_ID 1
#define DEVID_TYPE_NAA                  3

const value_string scsi_devid_idtype_val[] = {
    {0, "Vendor-specific ID (non-globally unique)"},
    {DEVID_TYPE_VEND_ID_VEND_SPEC_ID, "Vendor-ID + vendor-specific ID (globally unique)"},
    {2, "EUI-64 ID"},
    {DEVID_TYPE_NAA, "NAA"},
    {4, "4-byte Binary Number/Reserved"},
    {0, NULL},
};

static const value_string scsi_modesns_mrie_val[] = {
    {0, "No Reporting of Informational Exception Condition"},
    {1, "Asynchronous Error Reporting"},
    {2, "Generate Unit Attention"},
    {3, "Conditionally Generate Recovered Error"},
    {4, "Unconditionally Generate Recovered Error"},
    {5, "Generate No Sense"},
    {6, "Only Report Informational Exception Condition on Request"},
    {0, NULL},
};

static const value_string scsi_modesns_tst_val[] = {
    {0, "Task Set Per LU For All Initiators"},
    {1, "Task Set Per Initiator Per LU"},
    {0, NULL},
};

static const value_string scsi_modesns_qmod_val[] = {
    {0, "Restricted reordering"},
    {1, "Unrestricted reordering"},
    {0, NULL},
};

static const true_false_string scsi_modesns_qerr_val = {
    "All blocked tasks shall be aborted on CHECK CONDITION",
    "Blocked tasks shall resume after ACA/CA is cleared",
};

static const true_false_string scsi_spec_i_pt_tfs = {
    "Specify Initiator Ports is set",
    "Specify Initiator Ports is not set"
};

static const true_false_string scsi_all_tg_pt_tfs = {
    "All Target Ports is set",
    "All Target Ports is not set"
};

static const true_false_string scsi_aptpl_tfs = {
    "Active Persist Through Power Loss is set",
    "Active Persist Through Power Loss is not set"
};

static const true_false_string scsi_naca_tfs = {
    "Normal ACA is set",
    "Normal ACA is not set"
};

static const true_false_string normaca_tfs = {
    "NormACA is SUPPORTED",
    "Normaca is NOT supported",
};

static const true_false_string sccs_tfs = {
    "SCC is SUPPORTED",
    "Scc is NOT supported",
};

static const true_false_string acc_tfs = {
    "Access Control Coordinator is SUPPORTED",
    "Access control coordinator NOT supported",
};

static const true_false_string bque_tfs = {
    "BQUE is SUPPORTED",
    "Bque is NOT supported",
};

static const true_false_string encserv_tfs = {
    "Enclosed Services is SUPPORTED",
    "Enclosed services is NOT supported",
};

static const true_false_string reladr_tfs = {
    "Relative Addressing mode is SUPPORTED",
    "Relative addressing mode is NOT supported",
};

#if 0
static const true_false_string sync_tfs = {
    "Synchronous data transfer is SUPPORTED",
    "Synchronous data transfer is NOT supported",
};
#endif

static const true_false_string linked_tfs = {
    "Linked Commands are SUPPORTED",
    "Linked commands are NOT supported",
};

static const true_false_string cmdque_tfs = {
    "Command queuing is SUPPORTED",
    "Command queuing is NOT supported",
};

static const true_false_string multip_tfs = {
    "This is a MULTIPORT device",
    "This is NOT a multiport device",
};

static const true_false_string mchngr_tfs = {
    "This device is attached to a MEDIUMCHANGER",
    "This is a normal device",
};

static const true_false_string tpc_tfs = {
    "Third Party Copy is SUPPORTED",
    "Third party copy is NOT supported",
};

static const true_false_string protect_tfs = {
    "Protection Information is SUPPORTED",
    "Protection information NOT supported",
};

static const true_false_string hisup_tfs = {
    "Hierarchical Addressing Mode is SUPPORTED",
    "Hierarchical addressing mode is NOT supported",
};

static const true_false_string aerc_tfs = {
    "Async Event Reporting Capability is SUPPORTED",
    "Async event reporting capability is NOT supported",
};

static const true_false_string trmtsk_tfs = {
    "Terminate Task management functions are SUPPORTED",
    "Terminate task management functions are NOT supported",
};

static const true_false_string scsi_removable_val = {
    "This is a REMOVABLE device",
    "This device is NOT removable",
};

static const true_false_string scsi_modesns_tas_val = {
    "Terminated tasks aborted without informing initiators",
    "Tasks aborted by another initiator terminated with TASK ABORTED",
};

static const true_false_string scsi_modesns_rac_val = {
    "Report a CHECK CONDITION Instead of Long Busy Condition",
    "Long Busy Conditions Maybe Reported",
};

/* SCSI Transport Protocols */
#define SCSI_PROTO_FCP          0
#define SCSI_PROTO_iSCSI        5

static const value_string scsi_proto_val[] = {
    {0, "FCP"},
    {5, "iSCSI"},
    {0, NULL},
};

static const value_string scsi_fcp_rrtov_val[] = {
    {0, "No Timer Specified"},
    {1, "0.001 secs"},
    {3, "0.1 secs"},
    {5, "10 secs"},
    {0, NULL},
};

static const value_string scsi_sensekey_val[] = {
    {0x0, "No Sense"},
    {0x1, "Recovered Error"},
    {0x2, "Not Ready"},
    {0x3, "Medium Error"},
    {0x4, "Hardware Error"},
    {0x5, "Illegal Request"},
    {0x6, "Unit Attention"},
    {0x7, "Data Protection"},
    {0x8, "Blank Check"},
    {0x9, "Vendor Specific"},
    {0xA, "Copy Aborted"},
    {0xB, "Command Aborted"},
    {0xC, "Obsolete Error Code"},
    {0xD, "Overflow Command"},
    {0xE, "Miscompare"},
    {0xF, "Reserved"},
    {0, NULL},
};

static const value_string scsi_sense_desc_type_val[] = {
    {0x00, "Information"},
    {0x01, "Command specific information"},
    {0x02, "Sense key specific"},
    {0x03, "Field replaceable unit"},
    {0x04, "Stream commands"},
    {0x05, "Block commands"},
    {0x06, "OSD object identification"},
    {0x07, "OSD response integrity check value"},
    {0x08, "OSD attribute identification"},
    {0x09, "ATA Status"},
    {0x0A, "Another progress indication"},
    {0x0B, "User data segment referral"},
    {0x0C, "Forwarded sense data"},
    {0, NULL},
};

static const value_string scsi_sense_sks_fp_cd_val[] = {
    {0, "illegal parameter in the Data-Out buffer"},
    {1, "illegal parameter in the CDB"},
    {0, NULL},
};

static const value_string scsi_sns_errtype_val[] = {
    {0x70, "Current Error"},
    {0x71, "Deferred Error"},
    {0x72, "Current Error"},
    {0x73, "Deferred Error"},
    {0x7F, "Vendor Specific"},
    {0, NULL},
};

/* All can be found @ http://www.t10.org/lists/asc-alph.txt or http://www.t10.org/lists/asc-num.txt */
static const value_string scsi_asc_val[] = {
    {0x0000,  "No Additional Sense Information"},
    {0x0001,  "Filemark Detected"},
    {0x0002,  "End Of Partition/Medium Detected"},
    {0x0003,  "Setmark Detected"},
    {0x0004,  "Beginning Of Partition Detected"},
    {0x0005,  "End Of Data Detected"},
    {0x0006,  "I/O Process Terminated"},
    {0x0016,  "Operation In Progress"},
    {0x0017,  "Cleaning Requested"},
    {0x0018,  "Erase Operation In Progress"},
    {0x0019,  "Locate Operation In Progress"},
    {0x001A,  "Rewind Operation In Progress"},
    {0x001B,  "Set Capacity Operation In Progress"},
    {0x001C,  "Verify operation in progress"},
    {0x0100,  "No Index/Sector Signal"},
    {0x0200,  "No Seek Complete"},
    {0x0300,  "Peripheral Device Write Fault"},
    {0x0400,  "Logical Unit Not Ready, Cause Not Reportable"},
    {0x0401,  "Logical Unit Is In Process Of Becoming Ready"},
    {0x0402,  "Logical Unit Not Ready, Initializing Cmd. Required"},
    {0x0403,  "Logical Unit Not Ready, Manual Intervention Required"},
    {0x0404,  "Logical Unit Not Ready, Format In Progress"},
    {0x0405,  "Logical Unit Not Ready, Rebuild In Progress"},
    {0x0406,  "Logical Unit Not Ready, Recalculation In Progress"},
    {0x0407,  "Logical Unit Not Ready, Operation In Progress"},
    {0x0409,  "Logical Unit Not Ready, Self-Test In Progress"},
    {0x0500,  "Logical Unit Does Not Respond To Selection"},
    {0x0600,  "No Reference Position Found"},
    {0x0700,  "Multiple Peripheral Devices Selected"},
    {0x0800,  "Logical Unit Communication Failure"},
    {0x0801,  "Logical Unit Communication Time-Out"},
    {0x0802,  "Logical Unit Communication Parity Error"},
    {0x0803,  "Logical Unit Communication Crc Error (Ultra-Dma/32)"},
    {0x0804,  "Unreachable Copy Target"},
    {0x0900,  "Track Following Error"},
    {0x0904,  "Head Select Fault"},
    {0x0A00,  "Error Log Overflow"},
    {0x0B00,  "Warning"},
    {0x0B01,  "Warning - Specified Temperature Exceeded"},
    {0x0B02,  "Warning - Enclosure Degraded"},
    {0x0C02,  "Write Error - Auto Reallocation Failed"},
    {0x0C03,  "Write Error - Recommend Reassignment"},
    {0x0C04,  "Compression Check Miscompare Error"},
    {0x0C05,  "Data Expansion Occurred During Compression"},
    {0x0C06,  "Block Not Compressible"},
    {0x0D00,  "Error Detected By Third Party Temporary Initiator"},
    {0x0D01,  "Third Party Device Failure"},
    {0x0D02,  "Copy Target Device Not Reachable"},
    {0x0D03,  "Incorrect Copy Target Device Type"},
    {0x0D04,  "Copy Target Device Data Underrun"},
    {0x0D05,  "Copy Target Device Data Overrun"},
    {0x1000,  "Id Crc Or Ecc Error"},
    {0x1100,  "Unrecovered Read Error"},
    {0x1101,  "Read Retries Exhausted"},
    {0x1102,  "Error Too Long To Correct"},
    {0x1103,  "Multiple Read Errors"},
    {0x1104,  "Unrecovered Read Error - Auto Reallocate Failed"},
    {0x110A,  "Miscorrected Error"},
    {0x110B,  "Unrecovered Read Error - Recommend Reassignment"},
    {0x110C,  "Unrecovered Read Error - Recommend Rewrite The Data"},
    {0x110D,  "De-Compression Crc Error"},
    {0x110E,  "Cannot Decompress Using Declared Algorithm"},
    {0x1200,  "Address Mark Not Found For Id Field"},
    {0x1300,  "Address Mark Not Found For Data Field"},
    {0x1400,  "Recorded Entity Not Found"},
    {0x1401,  "Record Not Found"},
    {0x1405,  "Record Not Found - Recommend Reassignment"},
    {0x1406,  "Record Not Found - Data Auto-Reallocated"},
    {0x1500,  "Random Positioning Error"},
    {0x1501,  "Mechanical Positioning Error"},
    {0x1502,  "Positioning Error Detected By Read Of Medium"},
    {0x1600,  "Data Synchronization Mark Error"},
    {0x1601,  "Data Sync Error - Data Rewritten"},
    {0x1602,  "Data Sync Error - Recommend Rewrite"},
    {0x1603,  "Data Sync Error - Data Auto-Reallocated"},
    {0x1604,  "Data Sync Error - Recommend Reassignment"},
    {0x1700,  "Recovered Data With No Error Correction Applied"},
    {0x1701,  "Recovered Data With Retries"},
    {0x1702,  "Recovered Data With Positive Head Offset"},
    {0x1703,  "Recovered Data With Negative Head Offset"},
    {0x1705,  "Recovered Data Using Previous Sector Id"},
    {0x1706,  "Recovered Data Without Ecc - Data Auto-Reallocated"},
    {0x1707,  "Recovered Data Without Ecc - Recommend Reassignment"},
    {0x1708,  "Recovered Data Without Ecc - Recommend Rewrite"},
    {0x1709,  "Recovered Data Without Ecc - Data Rewritten"},
    {0x1800,  "Recovered Data With Error Correction Applied"},
    {0x1801,  "Recovered Data With Error Corr. & Retries Applied"},
    {0x1802,  "Recovered Data - Data Auto-Reallocated"},
    {0x1805,  "Recovered Data - Recommend Reassignment"},
    {0x1806,  "Recovered Data - Recommend Rewrite"},
    {0x1807,  "Recovered Data With Ecc - Data Rewritten"},
    {0x1900,  "List Error"},
    {0x1901,  "List Not Available"},
    {0x1902,  "List Error In Primary List"},
    {0x1903,  "List Error In Grown List"},
    {0x1A00,  "Parameter List Length Error"},
    {0x1B00,  "Synchronous Data Transfer Error"},
    {0x1C00,  "Defect List Not Found"},
    {0x1C01,  "Primary Defect List Not Found"},
    {0x1C02,  "Grown Defect List Not Found"},
    {0x1D00,  "Miscompare During Verify Operation"},
    {0x1E00,  "Recovered Id With Ecc Correction"},
    {0x1F00,  "Defect List Transfer"},
    {0x2000,  "Invalid Command Operation Code"},
    {0x2100,  "Logical Block Address Out Of Range"},
    {0x2101,  "Invalid Element Address"},
    {0x2400,  "Invalid Field In Cdb"},
    {0x2401,  "Cdb Decryption Error"},
    {0x2500,  "Logical Unit Not Supported"},
    {0x2600,  "Invalid Field In Parameter List"},
    {0x2601,  "Parameter Not Supported"},
    {0x2602,  "Parameter Value Invalid"},
    {0x2603,  "Threshold Parameters Not Supported"},
    {0x2604,  "Invalid Release Of Persistent Reservation"},
    {0x2605,  "Data Decryption Error"},
    {0x2606,  "Too Many Target Descriptors"},
    {0x2607,  "Unsupported Target Descriptor Type Code"},
    {0x2608,  "Too Many Segment Descriptors"},
    {0x2609,  "Unsupported Segment Descriptor Type Code"},
    {0x260A,  "Unexpected Inexact Segment"},
    {0x260B,  "Inline Data Length Exceeded"},
    {0x260C,  "Invalid Operation For Copy Source Or Destination"},
    {0x260D,  "Copy Segment Granularity Violation"},
    {0x2700,  "Write Protected"},
    {0x2701,  "Hardware Write Protected"},
    {0x2702,  "Logical Unit Software Write Protected"},
    {0x2800,  "Not Ready To Ready Change, Medium May Have Changed"},
    {0x2801,  "Import Or Export Element Accessed"},
    {0x2900,  "Power On, Reset, Or Bus Device Reset Occurred"},
    {0x2901,  "Power On Occurred"},
    {0x2902,  "Scsi Bus Reset Occurred"},
    {0x2903,  "Bus Device Reset Function Occurred"},
    {0x2904,  "Device Internal Reset"},
    {0x2905,  "Transceiver Mode Changed To Single-Ended"},
    {0x2906,  "Transceiver Mode Changed To Lvd"},
    {0x2A00,  "Parameters Changed"},
    {0x2A01,  "Mode Parameters Changed"},
    {0x2A02,  "Log Parameters Changed"},
    {0x2A03,  "Reservations Preempted"},
    {0x2A04,  "Reservations Released"},
    {0x2A05,  "Registrations Preempted"},
    {0x2B00,  "Copy Cannot Execute Since Host Cannot Disconnect"},
    {0x2C00,  "Command Sequence Error"},
    {0x2C0A,  "Partition or Collection Contains User Objects"},
    {0x2F00,  "Commands Cleared By Another Initiator"},
    {0x3000,  "Incompatible Medium Installed"},
    {0x3001,  "Cannot Read Medium - Unknown Format"},
    {0x3002,  "Cannot Read Medium - Incompatible Format"},
    {0x3003,  "Cleaning Cartridge Installed"},
    {0x3004,  "Cannot Write Medium - Unknown Format"},
    {0x3005,  "Cannot Write Medium - Incompatible Format"},
    {0x3006,  "Cannot Format Medium - Incompatible Medium"},
    {0x3007,  "Cleaning Failure"},
    {0x3100,  "Medium Format Corrupted"},
    {0x3101,  "Format Command Failed"},
    {0x3200,  "No Defect Spare Location Available"},
    {0x3201,  "Defect List Update Failure"},
    {0x3400,  "Enclosure Failure"},
    {0x3500,  "Enclosure Services Failure"},
    {0x3501,  "Unsupported Enclosure Function"},
    {0x3502,  "Enclosure Services Unavailable"},
    {0x3503,  "Enclosure Services Transfer Failure"},
    {0x3504,  "Enclosure Services Transfer Refused"},
    {0x3700,  "Rounded Parameter"},
    {0x3807,  "Thin Provisioning Soft Threshold Reached"},
    {0x3900,  "Saving Parameters Not Supported"},
    {0x3A00,  "Medium Not Present"},
    {0x3A01,  "Medium Not Present - Tray Closed"},
    {0x3A02,  "Medium Not Present - Tray Open"},
    {0x3A03,  "Medium Not Present - Loadable"},
    {0x3A04,  "Medium Not Present - Medium Auxiliary Memory Accessible"},
    {0x3B0D,  "Medium Destination Element Full"},
    {0x3B0E,  "Medium Source Element Empty"},
    {0x3B11,  "Medium Magazine Not Accessible"},
    {0x3B12,  "Medium Magazine Removed"},
    {0x3B13,  "Medium Magazine Inserted"},
    {0x3B14,  "Medium Magazine Locked"},
    {0x3B15,  "Medium Magazine Unlocked"},
    {0x3D00,  "Invalid Bits In Identify Message"},
    {0x3E00,  "Logical Unit Has Not Self-Configured Yet"},
    {0x3E01,  "Logical Unit Failure"},
    {0x3E02,  "Timeout On Logical Unit"},
    {0x3E03,  "Logical Unit Failed Self-Test"},
    {0x3E04,  "Logical Unit Unable To Update Self-Test Log"},
    {0x3F00,  "Target Operating Conditions Have Changed"},
    {0x3F01,  "Microcode Has Been Changed"},
    {0x3F02,  "Changed Operating Definition"},
    {0x3F03,  "Inquiry Data Has Changed"},
    {0x3F04,  "Component Device Attached"},
    {0x3F05,  "Device Identifier Changed"},
    {0x3F06,  "Redundancy Group Created Or Modified"},
    {0x3F07,  "Redundancy Group Deleted"},
    {0x3F08,  "Spare Created Or Modified"},
    {0x3F09,  "Spare Deleted"},
    {0x3F0A,  "Volume Set Created Or Modified"},
    {0x3F0B,  "Volume Set Deleted"},
    {0x3F0C,  "Volume Set Deassigned"},
    {0x3F0D,  "Volume Set Reassigned"},
    {0x3F0E,  "Reported Luns Data Has Changed"},
    {0x3F0F,  "Echo Buffer Overwritten"},
    {0x3F10,  "Medium Loadable"},
    {0x3F11,  "Medium Auxiliary Memory Accessible"},
    {0x4200,  "Self-Test Failure (Should Use 40 Nn)"},
    {0x4300,  "Message Error"},
    {0x4400,  "Internal Target Failure"},
    {0x4500,  "Select Or Reselect Failure"},
    {0x4600,  "Unsuccessful Soft Reset"},
    {0x4700,  "Scsi Parity Error"},
    {0x4701,  "Data Phase Crc Error Detected"},
    {0x4702,  "Scsi Parity Error Detected During St Data Phase"},
    {0x4703,  "Information Unit Crc Error Detected"},
    {0x4704,  "Asynchronous Information Protection Error Detected"},
    {0x4800,  "Initiator Detected Error Message Received"},
    {0x4900,  "Invalid Message Error"},
    {0x4A00,  "Command Phase Error"},
    {0x4B00,  "Data Phase Error"},
    {0x4C00,  "Logical Unit Failed Self-Configuration"},
    {0x4D00,  "Tagged Overlapped Commands (Nn = Queue Tag)"},
    {0x4E00,  "Overlapped Commands Attempted"},
    {0x5300,  "Media Load Or Eject Failed"},
    {0x5302,  "Medium Removal Prevented"},
    {0x5501,  "System Buffer Full"},
    {0x5502,  "Insufficient Reservation Resources"},
    {0x5503,  "Insufficient Resources"},
    {0x5504,  "Insufficient Registration Resources"},
    {0x5A00,  "Operator Request Or State Change Input"},
    {0x5A01,  "Operator Medium Removal Request"},
    {0x5A02,  "Operator Selected Write Protect"},
    {0x5A03,  "Operator Selected Write Permit"},
    {0x5B00,  "Log Exception"},
    {0x5B01,  "Threshold Condition Met"},
    {0x5B02,  "Log Counter At Maximum"},
    {0x5B03,  "Log List Codes Exhausted"},
    {0x5C00,  "Change"},
    {0x5C02,  "Synchronized"},
    {0x5D00,  "Failure Prediction Threshold Exceeded"},
    {0x5D10,  "Failure General Hard Drive Failure"},
    {0x5D11,  "Failure Drive Error Rate Too High"},
    {0x5D12,  "Failure Data Error Rate Too High"},
    {0x5D13,  "Failure Seek Error Rate Too High"},
    {0x5D14,  "Failure Too Many Block Reassigns"},
    {0x5D15,  "Failure Access Times Too High"},
    {0x5D16,  "Failure Start Unit Times Too High"},
    {0x5D17,  "Failure Channel Parametrics"},
    {0x5D18,  "Failure Controller Detected"},
    {0x5D19,  "Failure Throughput Performance"},
    {0x5D1A,  "Failure Seek Time Performance"},
    {0x5D1B,  "Failure Spin-Up Retry Count"},
    {0x5D1C,  "Failure Drive Calibration Retry"},
    {0x5D20,  "Failure General Hard Drive Failure"},
    {0x5D21,  "Failure Drive Error Rate Too High"},
    {0x5D22,  "Failure Data Error Rate Too High"},
    {0x5D23,  "Failure Seek Error Rate Too High"},
    {0x5D24,  "Failure Too Many Block Reassigns"},
    {0x5D25,  "Failure Access Times Too High"},
    {0x5D26,  "Failure Start Unit Times Too High"},
    {0x5D27,  "Failure Channel Parametrics"},
    {0x5D28,  "Failure Controller Detected"},
    {0x5D29,  "Failure Throughput Performance"},
    {0x5D2A,  "Failure Seek Time Performance"},
    {0x5D2B,  "Failure Spin-Up Retry Count"},
    {0x5D2C,  "Failure Drive Calibration Retry"},
    {0x5D30,  "Impending Failure General Hard Drive"},
    {0x5D31,  "Impending Failure Drive Error Rate Too High"},
    {0x5D32,  "Impending Failure Data Error Rate Too High"},
    {0x5D33,  "Impending Failure Seek Error Rate Too High"},
    {0x5D34,  "Impending Failure Too Many Block Reassigns"},
    {0x5D35,  "Impending Failure Access Times Too High"},
    {0x5D36,  "Impending Failure Start Unit Times Too High"},
    {0x5D37,  "Impending Failure Channel Parametrics"},
    {0x5D38,  "Impending Failure Controller Detected"},
    {0x5D39,  "Impending Failure Throughput Performance"},
    {0x5D3A,  "Impending Failure Seek Time Performance"},
    {0x5D3B,  "Impending Failure Spin-Up Retry Count"},
    {0x5D3C,  "Impending Failure Drive Calibration Retry"},
    {0x5D40,  "Failure General Hard Drive Failure"},
    {0x5D41,  "Failure Drive Error Rate Too High"},
    {0x5D42,  "Failure Data Error Rate Too High"},
    {0x5D43,  "Failure Seek Error Rate Too High"},
    {0x5D44,  "Failure Too Many Block Reassigns"},
    {0x5D45,  "Failure Access Times Too High"},
    {0x5D46,  "Failure Start Unit Times Too High"},
    {0x5D47,  "Failure Channel Parametrics"},
    {0x5D48,  "Failure Controller Detected"},
    {0x5D49,  "Failure Throughput Performance"},
    {0x5D4A,  "Failure Seek Time Performance"},
    {0x5D4B,  "Failure Spin-Up Retry Count"},
    {0x5D4C,  "Failure Drive Calibration Retry Count"},
    {0x5D50,  "Failure General Hard Drive Failure"},
    {0x5D51,  "Failure Drive Error Rate Too High"},
    {0x5D52,  "Failure Data Error Rate Too High"},
    {0x5D53,  "Failure Seek Error Rate Too High"},
    {0x5D54,  "Failure Too Many Block Reassigns"},
    {0x5D55,  "Failure Access Times Too High"},
    {0x5D56,  "Failure Start Unit Times Too High"},
    {0x5D57,  "Failure Channel Parametrics"},
    {0x5D58,  "Failure Controller Detected"},
    {0x5D59,  "Failure Throughput Performance"},
    {0x5D5A,  "Failure Seek Time Performance"},
    {0x5D5B,  "Failure Spin-Up Retry Count"},
    {0x5D5C,  "Failure Drive Calibration Retry Count"},
    {0x5D60,  "Failure General Hard Drive Failure"},
    {0x5D61,  "Failure Drive Error Rate Too High"},
    {0x5D62,  "Failure Data Error Rate Too High"},
    {0x5D63,  "Failure Seek Error Rate Too High"},
    {0x5D64,  "Failure Too Many Block Reassigns"},
    {0x5D65,  "Failure Access Times Too High"},
    {0x5D66,  "Failure Start Unit Times Too High"},
    {0x5D67,  "Failure Channel Parametrics"},
    {0x5D68,  "Failure Controller Detected"},
    {0x5D69,  "Failure Throughput Performance"},
    {0x5D6A,  "Failure Seek Time Performance"},
    {0x5D6B,  "Failure Spin-Up Retry Count"},
    {0x5D6C,  "Failure Drive Calibration Retry Count"},
    {0x5DFF,  "Failure Prediction Threshold Exceeded (False)"},
    {0x5E00,  "Low Power Condition On"},
    {0x5E01,  "Idle Condition Activated By Timer"},
    {0x5E02,  "Standby Condition Activated By Timer"},
    {0x5E03,  "Idle Condition Activated By Command"},
    {0x5E04,  "Standby Condition Activated By Command"},
    {0x6500,  "Voltage Fault"},
    {0, NULL},
};
value_string_ext scsi_asc_val_ext = VALUE_STRING_EXT_INIT(scsi_asc_val);

/* SCSI Status Codes */
const value_string scsi_status_val[] = {
    {0x00, "Good"},
    {0x02, "Check Condition"},
    {0x04, "Condition Met"},
    {0x08, "Busy"},
    {0x10, "Intermediate"},
    {0x14, "Intermediate Condition Met"},
    {0x18, "Reservation Conflict"},
    {0x28, "Task Set Full"},
    {0x30, "ACA Active"},
    {0x40, "Task Aborted"},
    {0, NULL},
};


const value_string scsi_wb_mode_val[] = {
    {0x0, "Write combined header and data"},
    {0x1, "Vendor specific"},
    {0x2, "Write data"},
    {0x3, "Reserved"},
    {0x4, "Download microcode"},
    {0x5, "Download microcode and save"},
    {0x6, "Download microcode with offsets"},
    {0x7, "Download microcode with offsets and save"},
    {0x8, "Reserved"},
    {0x9, "Reserved"},
    {0xA, "Echo buffer"},
    {0, NULL},
};

const value_string scsi_senddiag_st_code_val[] = {
    {0, ""},
    {0x1, "Start short self-test in background"},
    {0x2, "Start extended self-test in background"},
    {0x3, "Reserved"},
    {0x4, "Abort background self-test"},
    {0x5, "Foreground short self-test"},
    {0x6, "Foreground extended self-test"},
    {0x7, "Reserved"},
    {0, NULL},
};

const true_false_string scsi_senddiag_pf_val = {
    "Standard Page Format",
    "Vendor-specific Page Format",
};

static gint scsi_def_devtype = SCSI_DEV_SBC;


typedef struct _cmdset_t {
    int                 hf_opcode;
    value_string_ext   *cdb_vals_ext;
    scsi_cdb_table_t   *cdb_table;
} cmdset_t;

static cmdset_t *get_cmdset_data(itlq_nexus_t *itlq, itl_nexus_t *itl);

static void
dissect_naa_designator(proto_tree *tree, tvbuff_t *tvb, guint offset, guint len)
{
        proto_tree *naa_tree;
        guint8 naa_type;
        guint64 vs;

        naa_type = tvb_get_guint8(tvb, offset) >> 4;

        naa_tree = proto_tree_add_subtree_format(tree, tvb, offset, len,
                        ett_scsi_naa, NULL, "NAA Designator: %s",
                        val_to_str(naa_type,
                                   scsi_naa_designator_type_val,
                                   "Unknown (0x%08x)"));

        proto_tree_add_item(naa_tree, hf_scsi_naa_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        switch(naa_type) {
        case NAA_TYPE_IEEE_EXTENDED:
            vs = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(naa_tree, hf_scsi_naa_vendor_specific, tvb, offset, 2, (guint)((vs >> 48) & 0x0fff));
            proto_tree_add_item(naa_tree, hf_scsi_naa_ieee_company_id, tvb, offset + 2, 3, ENC_BIG_ENDIAN);
            proto_tree_add_uint(naa_tree, hf_scsi_naa_vendor_specific, tvb, offset + 5, 3, (guint)(vs & 0x00ffffff));
            break;
        case NAA_TYPE_LOCALLY_ASSIGNED:
            proto_tree_add_item(naa_tree, hf_scsi_naa_locally_assigned, tvb, offset + 1, len - 1, ENC_NA);
            break;
        case NAA_TYPE_IEEE_REGISTERED:
            vs = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(naa_tree, hf_scsi_naa_ieee_company_id, tvb, offset, 4, (guint)((vs >> 36) & 0x00ffffff));
            proto_tree_add_uint(naa_tree, hf_scsi_naa_vendor_specific, tvb, offset + 3, 4, (guint)(vs & 0x0fffffff));
            break;
        case NAA_TYPE_IEEE_REGISTERED_EXTENDED:
            vs = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(naa_tree, hf_scsi_naa_ieee_company_id, tvb, offset, 4, (guint)((vs >> 36) & 0x00ffffff));
            proto_tree_add_uint(naa_tree, hf_scsi_naa_vendor_specific, tvb, offset + 3, 4, (guint)(vs & 0x0fffffff));
            proto_tree_add_item(naa_tree, hf_scsi_naa_vendor_specific_extension, tvb, offset + 8, 8, ENC_NA);
            break;
        }
}


static void
dissect_scsi_evpd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                  guint offset, guint tot_len _U_)
{
    proto_tree *evpd_tree;
    proto_item *ti;
    guint       pcode, plen, i, idlen;
    guint8      codeset, identifier_type;
    proto_tree *des_tree;

    if (tree) {
        pcode = tvb_get_guint8(tvb, offset+1);
        plen = tvb_get_guint8(tvb, offset+3);
        evpd_tree = proto_tree_add_subtree_format(tree, tvb, offset, plen+4,
                                 ett_scsi_page, NULL, "Page Code: %s",
                                 val_to_str(pcode, scsi_evpd_pagecode_val,
                                            "Unknown (0x%08x)"));

        proto_tree_add_item(evpd_tree, hf_scsi_inq_qualifier, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(evpd_tree, hf_scsi_inq_devtype, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(evpd_tree, hf_scsi_inquiry_evpd_page, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(evpd_tree, hf_scsi_inq_evpd_page_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        offset += 4;
        switch (pcode) {
        case SCSI_EVPD_SUPPPG:
            for (i = 0; i < plen; i++) {
                proto_tree_add_item(evpd_tree, hf_scsi_inq_evpd_supported_page, tvb, offset+i, 1, ENC_BIG_ENDIAN);
            }
            break;
        case SCSI_EVPD_DEVID:
            i = 0;
            while (plen != 0) {
                idlen = tvb_get_guint8(tvb, offset + 3);

                des_tree = proto_tree_add_subtree_format(evpd_tree,
                        tvb, offset, idlen, ett_scsi_designation_descriptor,
                        NULL, "Designation Descriptor");

                i++;
                ti = proto_tree_add_uint(des_tree, hf_scsi_inq_evpd_identifier_number, tvb, offset, 0, i);
                PROTO_ITEM_SET_GENERATED(ti);

                codeset = tvb_get_guint8(tvb, offset) & 0x0F;
                ti = proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_code_set, tvb, offset, 1, ENC_BIG_ENDIAN);
                plen -= 1;
                offset += 1;

                if (plen < 1) {
                    expert_add_info(pinfo, ti, &ei_scsi_product_data_goes_past_end_of_page);
                    break;
                }

                proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_association, tvb, offset, 1, ENC_BIG_ENDIAN);
                identifier_type = tvb_get_guint8(tvb, offset);
                ti = proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_identifier_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                plen -= 1;
                offset += 1;

                /* Skip reserved byte */
                if (plen < 1) {
                    expert_add_info(pinfo, ti, &ei_scsi_product_data_goes_past_end_of_page);
                    break;
                }
                plen -= 1;
                offset += 1;

                if (plen < 1) {
                    expert_add_info(pinfo, ti, &ei_scsi_product_data_goes_past_end_of_page);
                    break;
                }
                ti = proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_identifier_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                plen -= 1;
                offset += 1;

                if (idlen != 0) {
                    if (plen < idlen) {
                        expert_add_info(pinfo, ti, &ei_scsi_product_data_goes_past_end_of_page);
                        break;
                    }
                    if (codeset == CODESET_ASCII) {
                        if (identifier_type == DEVID_TYPE_VEND_ID_VEND_SPEC_ID) {
                            proto_tree_add_item(des_tree, hf_scsi_inq_vendor_id, tvb, offset, 8, ENC_ASCII|ENC_NA);
                            proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_identifier_str, tvb, offset + 8, idlen - 8, ENC_NA|ENC_ASCII);
                        } else {
                            proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_identifier_str, tvb, offset, idlen, ENC_NA|ENC_ASCII);
                        }
                    } else if (codeset == CODESET_BINARY && identifier_type == DEVID_TYPE_NAA) {
                        dissect_naa_designator(des_tree, tvb, offset, idlen);
                    } else {
                        /*
                         * XXX - decode this based on the identifier type,
                         * if the codeset is CODESET_BINARY?
                         */
                        proto_tree_add_item(des_tree, hf_scsi_inq_evpd_devid_identifier_bytes, tvb, offset, idlen, ENC_NA);
                    }
                    plen -= idlen;
                    offset += idlen;
                }
            }
            break;
        case SCSI_EVPD_DEVSERNUM:
            if (plen > 0) {
                proto_tree_add_item(evpd_tree, hf_scsi_inq_evpd_product_serial_number, tvb, offset, plen, ENC_NA|ENC_ASCII);
            }
            break;
        case SCSI_EVPD_BLKDEVCHAR:
            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_mrr, tvb,
                offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_pt, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_wabereq, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_wacereq, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_nff, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_fuab, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(evpd_tree, hf_scsi_inquiry_bdc_vbuls, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            /*offset += 1;*/
        break;
        case SCSI_EVPD_BLKLIMITS:
            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_wsnz, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mcawl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_otlg, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mtl, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_otl, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mpl, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mulc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mubdc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_oug, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_ugavalid, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_uga, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_mwsl, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_matl, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_aa, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(evpd_tree, hf_scsi_block_limits_atlg, tvb, offset, 4, ENC_BIG_ENDIAN);
            /*offset += 4;*/

            break;
        case SCSI_EVPD_LBP:
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_threshold_exponent, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_sbc_lbpu, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_lbpws, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_lbpws10, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_lbprz, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_anc_sup, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(evpd_tree, hf_scsi_sbc_dp, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(evpd_tree, hf_scsi_sbc_ptype, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*offset += 1;*/

            break;
        }
    }
}

static void
dissect_scsi_cmddt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint offset, guint tot_len _U_)
{
    proto_tree *cmdt_tree;
    guint       plen;

    if (tree) {
        plen = tvb_get_guint8(tvb, offset+5);
        cmdt_tree = proto_tree_add_subtree_format(tree, tvb, offset, plen, ett_scsi_page, NULL, "Command Data");

        proto_tree_add_item(cmdt_tree, hf_scsi_inq_qualifier, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cmdt_tree, hf_scsi_inq_devtype, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cmdt_tree, hf_scsi_inq_cmddt_support, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cmdt_tree, hf_scsi_inq_cmddt_version, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cmdt_tree, hf_scsi_inq_cmddt_cdb_size, tvb, offset+5, 1, ENC_BIG_ENDIAN);
    }
}


#define SCSI_INQ_ACAFLAGS_AERC      0x80
#define SCSI_INQ_ACAFLAGS_TRMTSK    0x40
#define SCSI_INQ_ACAFLAGS_NORMACA   0x20
#define SCSI_INQ_ACAFLAGS_HISUP     0x10

static const value_string inq_rdf_vals[] = {
    { 2, "SPC-2/SPC-3/SPC-4" },
    { 0, NULL }
};


#define SCSI_INQ_SCCSFLAGS_SCCS     0x80
#define SCSI_INQ_SCCSFLAGS_ACC      0x40
#define SCSI_INQ_SCCSFLAGS_TPC      0x08
#define SCSI_INQ_SCCSFLAGS_PROTECT  0x01

static const value_string inq_tpgs_vals[] = {
    { 0, "Asymmetric LU Access not supported" },
    { 1, "Implicit Asymmetric LU Access supported" },
    { 2, "Explicit LU Access supported" },
    { 3, "Both Implicit and Explicit LU Access supported" },
    { 0, NULL }
};

/* This dissects byte 5 of the SPC/SPC-2/SPC-3/SPC-4 standard INQ data */
static int
dissect_spc_inq_sccsflags(tvbuff_t *tvb, int offset, proto_tree *tree, int version)
{
    static const int *sccs_fields_spc2[] = {
        &hf_scsi_inq_sccs,
        NULL
    };
    static const int *sccs_fields_spc3[] = {
        &hf_scsi_inq_sccs,
        &hf_scsi_inq_acc,
        &hf_scsi_inq_tpgs,
        &hf_scsi_inq_tpc,
        &hf_scsi_inq_protect,
        NULL
    };

    switch (version) {
    case 3: /* SPC */
        break;
    case 4: /* SPC-2 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_sccsflags, ett_scsi_inq_sccsflags,  sccs_fields_spc2, ENC_BIG_ENDIAN);
        break;
    case 5: /* SPC-3 */
    case 6: /* SPC-4 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_sccsflags, ett_scsi_inq_sccsflags,  sccs_fields_spc3, ENC_BIG_ENDIAN);
        break;
    default: /* including version 0 : claims conformance to no standard */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_sccsflags, ett_scsi_inq_sccsflags,  sccs_fields_spc3, ENC_BIG_ENDIAN);
    }

    offset += 1;
    return offset;
}


#define SCSI_INQ_BQUEFLAGS_BQUE     0x80
#define SCSI_INQ_BQUEFLAGS_ENCSERV  0x40
#define SCSI_INQ_BQUEFLAGS_MULTIP   0x10
#define SCSI_INQ_BQUEFLAGS_MCHNGR   0x08
#define SCSI_INQ_BQUEFLAGS_ACKREQQ  0x04

/* This dissects byte 6 of the SPC/SPC-2/SPC-3/SPC-4 standard INQ data */
static int
dissect_spc_inq_bqueflags(tvbuff_t *tvb, int offset, proto_tree *tree, int version)
{
    static const int *bqe_fields_spc[] = {
        &hf_scsi_inq_encserv,
        &hf_scsi_inq_multip,
        &hf_scsi_inq_mchngr,
        &hf_scsi_inq_ackreqq,
        NULL
    };
    static const int *bqe_fields_spc2[] = {
        &hf_scsi_inq_bque,
        &hf_scsi_inq_encserv,
        &hf_scsi_inq_multip,
        &hf_scsi_inq_mchngr,
        NULL
    };
    static const int *bqe_fields_spc4[] = {
        &hf_scsi_inq_bque,
        &hf_scsi_inq_encserv,
        &hf_scsi_inq_multip,
        NULL
    };

    switch (version) {
    case 3: /* SPC */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_bqueflags, ett_scsi_inq_bqueflags,  bqe_fields_spc, ENC_BIG_ENDIAN);
        break;
    case 4: /* SPC-2 */
    case 5: /* SPC-3 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_bqueflags, ett_scsi_inq_bqueflags,  bqe_fields_spc2, ENC_BIG_ENDIAN);
        break;
    case 6: /* SPC-4 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_bqueflags, ett_scsi_inq_bqueflags,  bqe_fields_spc4, ENC_BIG_ENDIAN);
        break;
    default: /* including version 0 : claims conformance to no standard */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_bqueflags, ett_scsi_inq_bqueflags,  bqe_fields_spc4, ENC_BIG_ENDIAN);
        break;
    }

    offset+=1;
    return offset;
}

#define SCSI_INQ_RELADRFLAGS_RELADR     0x80
#define SCSI_INQ_RELADRFLAGS_LINKED     0x08
#define SCSI_INQ_RELADRFLAGS_TRANDIS    0x04
#define SCSI_INQ_RELADRFLAGS_CMDQUE     0x02

/* This dissects byte 7 of the SPC/SPC-2/SPC-3/SPC-4 standard INQ data */
static int
dissect_spc_inq_reladrflags(tvbuff_t *tvb, int offset, proto_tree *tree, int version)
{
    static const int *reladr_fields_spc[] = {
        &hf_scsi_inq_reladr,
        &hf_scsi_inq_linked,
        &hf_scsi_inq_trandis,
        &hf_scsi_inq_cmdque,
        NULL
    };
    static const int *reladr_fields_spc2[] = {
        &hf_scsi_inq_reladr,
        &hf_scsi_inq_linked,
        &hf_scsi_inq_cmdque,
        NULL
    };
    static const int *reladr_fields_spc3[] = {
        &hf_scsi_inq_linked,
        &hf_scsi_inq_cmdque,
        NULL
    };
    static const int *reladr_fields_spc4[] = {
        &hf_scsi_inq_cmdque,
        NULL
    };


    switch (version) {
    case 3: /* SPC */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_reladrflags, ett_scsi_inq_reladrflags,  reladr_fields_spc, ENC_BIG_ENDIAN);
        break;
    case 4: /* SPC-2 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_reladrflags, ett_scsi_inq_reladrflags,  reladr_fields_spc2, ENC_BIG_ENDIAN);
        break;
    case 5: /* SPC-3 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_reladrflags, ett_scsi_inq_reladrflags,  reladr_fields_spc3, ENC_BIG_ENDIAN);
        break;
    case 6: /* SPC-4 */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_reladrflags, ett_scsi_inq_reladrflags,  reladr_fields_spc4, ENC_BIG_ENDIAN);
        break;
    default: /* including version 0 : claims conformance to no standard */
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_inq_reladrflags, ett_scsi_inq_reladrflags,  reladr_fields_spc4, ENC_BIG_ENDIAN);
    }

    offset+=1;
    return offset;
}

static const int *peripheral_fields[] = {
    &hf_scsi_inq_qualifier,
    &hf_scsi_inq_devtype,
    NULL
};


void
dissect_spc_inquiry(tvbuff_t *tvb_a, packet_info *pinfo,
                    proto_tree *tree, guint offset_a, gboolean isreq,
                    gboolean iscdb, guint32 payload_len,
                    scsi_task_data_t *cdata)
{
    guint8             flags, i, version;

    static const int *inq_control_fields[] = {
        &hf_scsi_inq_control_vendor_specific,
        &hf_scsi_inq_control_reserved,
        &hf_scsi_inq_control_naca,
        &hf_scsi_inq_control_obs1,
        &hf_scsi_inq_control_obs2,
        NULL
    };
    static const int *aca_fields_spc[] = {
        &hf_scsi_inq_aerc,  /* obsolete in spc3 and forward */
        &hf_scsi_inq_trmtsk,/* obsolete in spc2 and forward */
        &hf_scsi_inq_normaca,
        &hf_scsi_inq_hisup,
        &hf_scsi_inq_rdf,
        NULL
    };
    static const int *aca_fields_spc2[] = {
        &hf_scsi_inq_aerc,      /* obsolete in spc3 and forward */
        &hf_scsi_inq_normaca,
        &hf_scsi_inq_hisup,
        &hf_scsi_inq_rdf,
        NULL
    };
    static const int *aca_fields_spc3[] = {
        &hf_scsi_inq_normaca,
        &hf_scsi_inq_hisup,
        &hf_scsi_inq_rdf,
        NULL
    };
    static const int *rmb_fields[] = {
        &hf_scsi_inq_rmb,
        NULL
    };

    if (!isreq && ((cdata == NULL) || !(cdata->itlq->flags & 0x3))
        && (tvb_reported_length_remaining(tvb_a, offset_a) >= 1) ) {
        /*
         * INQUIRY response with device type information; add device type
         * to list of known devices & their types if not already known.
         */
        if (cdata && cdata->itl) {
            cdata->itl->cmdset = tvb_get_guint8(tvb_a, offset_a)&SCSI_DEV_BITS;
        }
    }

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb_a, offset_a);
        if (cdata) {
            cdata->itlq->flags = flags;
        }

        proto_tree_add_uint_format(tree, hf_scsi_inquiry_flags, tvb_a, offset_a, 1,
                                   flags, "CMDT = %u, EVPD = %u",
                                   flags & 0x2, flags & 0x1);
        if (flags & 0x1) {
            proto_tree_add_item(tree, hf_scsi_inquiry_evpd_page, tvb_a, offset_a+1,
                                1, ENC_BIG_ENDIAN);

        col_add_fstr(pinfo->cinfo, COL_INFO, " %s",
             val_to_str(tvb_get_guint8(tvb_a, offset_a+1),
                    scsi_evpd_pagecode_val,
                    "Unknown VPD 0x%02x"));
        } else if (flags & 0x2) {
            proto_tree_add_item(tree, hf_scsi_inquiry_cmdt_page, tvb_a, offset_a+1,
                                1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(tree, hf_scsi_alloclen16, tvb_a, offset_a+2, 2, ENC_BIG_ENDIAN);
        /* we need the alloc_len in the response */
        if (cdata) {
            cdata->itlq->alloc_len = tvb_get_ntohs(tvb_a, offset_a+2);
        }
        proto_tree_add_bitmask(tree, tvb_a, offset_a+4, hf_scsi_inq_control,
                               ett_scsi_inq_control, inq_control_fields, ENC_BIG_ENDIAN);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }

        if (cdata->itlq->flags & 0x1) {
            dissect_scsi_evpd(tvb_a, pinfo, tree, offset_a, payload_len);
            return;
        }
        if (cdata->itlq->flags & 0x2) {
            dissect_scsi_cmddt(tvb_a, pinfo, tree, offset_a, payload_len);
            return;
        }

        /* These pdus are sometimes truncated by SCSI allocation length
         * in the CDB
         */
        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */

        /* Qualifier and DeviceType */
        proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_peripheral, ett_scsi_inq_peripheral, peripheral_fields, ENC_BIG_ENDIAN);
        try_offset+=1;

        /* RMB */
        proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_rmbflags, ett_scsi_inq_rmbflags, rmb_fields, ENC_BIG_ENDIAN);
        try_offset+=1;

        /* Version */
        version = tvb_get_guint8(try_tvb, try_offset);
        proto_tree_add_item(tree, hf_scsi_inq_version, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
        try_offset+=1;

        /* aca flags */
        switch (version) {
        case 3: /* SPC */
            proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_acaflags, ett_scsi_inq_acaflags, aca_fields_spc, ENC_BIG_ENDIAN);
            break;
        case 4: /* SPC-2 */
            proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_acaflags, ett_scsi_inq_acaflags, aca_fields_spc2, ENC_BIG_ENDIAN);
            break;
        case 5: /* SPC-3 */
        case 6: /* SPC-4 */
            proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_acaflags, ett_scsi_inq_acaflags, aca_fields_spc3, ENC_BIG_ENDIAN);
            break;
        default: /* including version 0 : claims conformance to no standard */
            proto_tree_add_bitmask(tree, try_tvb, try_offset, hf_scsi_inq_acaflags, ett_scsi_inq_acaflags, aca_fields_spc3, ENC_BIG_ENDIAN);
        }
        try_offset+=1;

        /* Additional Length */
        SET_SCSI_DATA_END(tvb_get_guint8(try_tvb, try_offset)+try_offset);
        proto_tree_add_item(tree, hf_scsi_inq_add_len, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
        try_offset+=1;

        /* sccs flags */
        try_offset = dissect_spc_inq_sccsflags(try_tvb, try_offset, tree, version);

        /* bque flags */
        try_offset = dissect_spc_inq_bqueflags(try_tvb, try_offset, tree, version);

        /* reladdr flags */
        try_offset = dissect_spc_inq_reladrflags(try_tvb, try_offset, tree, version);

        /* vendor id */
        proto_tree_add_item(tree, hf_scsi_inq_vendor_id, try_tvb, try_offset, 8, ENC_ASCII|ENC_NA);
        try_offset+=8;

        /* product id */
        proto_tree_add_item(tree, hf_scsi_inq_product_id, try_tvb, try_offset, 16, ENC_ASCII|ENC_NA);
        try_offset+=16;

        /* product revision level */
        proto_tree_add_item(tree, hf_scsi_inq_product_rev, try_tvb, try_offset, 4, ENC_ASCII|ENC_NA);
        try_offset+=4;

        /* vendor specific, 20 bytes */
        proto_tree_add_item(tree, hf_scsi_inq_vendor_specific, try_tvb, try_offset, 20, ENC_NA);
        try_offset+=20;

        /* reserved */
        try_offset += 2;

        /* version descriptors */
        for(i = 0;i<8;i++) {
            proto_tree_add_item(tree, hf_scsi_inq_version_desc, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
            try_offset+=2;
        }

        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

#define XCOPY_LID1 0
#define XCOPY_LID4 1
static const value_string extcopy_service_vals[] = {
       { XCOPY_LID1, "Extended Copy (LID1)" },
        { XCOPY_LID4, "Extended Copy (LID4)" },
        { 0, NULL }
};

#define RECV_COPY_PARAMS 0x3
static const value_string recv_copy_service_vals[] = {
        { 0x6, "Receive Copy Data (LID4)" },
        { 0x1, "Receive Copy Data (LID1)" },
        { RECV_COPY_PARAMS, "Receive Copy Parameters" },
        { 0x4, "Receive Copy Failure details" },
        { 0x5, "Receive Copy Status (LID4)" },
        { 0x0, "Receive Copy Status (LID1)" },
        { 0, NULL }
};


#if 0
static const value_string cscd_desc_type_code_vals[] = {
        { 0xE0, "Fibre Channel N_Port_Name CSCD descriptor" },
        { 0xE1, "Fibre Channel N_Port_ID CSCD descriptor" },
        { 0xE2, "Fibre Channel N_Port_ID With N_Port_Name Checking CSCD descriptor" },
        { 0xE3, "Parallel Interface T_L CSCD descriptor" },
        { 0xE4, "Identification Descriptor CSCD descriptor" },
        { 0xFF, "Extension descriptor" },
        { 0, NULL }
};
#endif

static const int *per_dev_type_bitmask_fields[] = {
        &hf_scsi_spc_xcopy_lu_type,
        &hf_scsi_spc_xcopy_per_dev_type,
        NULL
};

static const int *xcopy_param_list_bits[] = {
        &hf_scsi_spc_xcopy_param_str,
        &hf_scsi_spc_xcopy_param_list_id_usage,
        &hf_scsi_spc_xcopy_param_priority,
        NULL
};

#define BLOCK_DEV_0 0x0
#define BLOCK_DEV_4 0x4
#define BLOCK_DEV_5 0x5
#define BLOCK_DEV_7 0x7
#define BLOCK_DEV_E 0xE

static const value_string per_dev_type_vals[] = {
        { BLOCK_DEV_0, "Block devices" },
        { 0x1, "Sequential access devices" },
        { 0x3, "Processor devices" },
        { BLOCK_DEV_4, "Block devices" },
        { BLOCK_DEV_5, "Block devices" },
        { BLOCK_DEV_7, "Block devices" },
        { BLOCK_DEV_E, "Block devices" },
        { 0, NULL }
};

static const value_string lu_type_vals[] = {
        { 0, "Logical Unit Number" },
        { 1, "Proxy Token" },
        { 2, "Reserved" },
        { 3, "Reserved" },
        { 0, NULL }
};

#define BLOCK_TO_BLOCK 2

static const range_string desc_type_rval[] = {
        { 0x0, 0x0, "Block to stream" },
        { 0x1, 0x1, "Stream to block" },
        { BLOCK_TO_BLOCK, BLOCK_TO_BLOCK, "Block to block" },
        { 0x3, 0x3, "Stream to stream" },
        { 0x4, 0x4, "Inline to stream" },
        { 0x5, 0x5, "Embedded to strem" },
        { 0x6, 0x6, "Stream to discard" },
        { 0x7, 0x7, "Verify CSCD" },
        { 0x0, 0xBF, "Segment descriptors" },
        { 0xC, 0xDF, "Vendor-specific descriptors" },
        { 0xE0, 0xE0, "Fibre Channel N_Port_Name CSCD descriptor" },
        { 0xE1,  0xE1, "Fibre Channel N_Port_ID CSCD descriptor" },
        { 0xE2, 0xE2, "Fibre Channel N_Port_ID With N_Port_Name Checking CSCD descriptor" },
        { 0xE3, 0xE3, "Parallel Interface T_L CSCD descriptor" },
        { 0xE4, 0xE4, "Identification Descriptor CSCD descriptor" },
        { 0xE5, 0xFE, "CSCD descriptors" },
        { 0xFF, 0xFF, "CSCD descriptor extension" },
        { 0, 0, NULL }
};

void
dissect_spc_extcopy(tvbuff_t *tvb, packet_info *pinfo _U_,
                    proto_tree *tree, guint offset,
                    gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata)
{
        guint16 serv_action;
        guint8 cscd_desc_type, dev_type, des_len, code_set, des_type, seg_type;
        guint16 cscd_desc_list_len, seg_desc_len;
        guint32 /*param_list_len,*/ seg_desc_list_len, inline_data_len, i;
        proto_tree *cscds_tree = NULL, *dev_tree = NULL, *cscd_tree = NULL, *segs_tree = NULL,
                   *seg_tree = NULL, *seg_param_tree = NULL, *cscd_desc_tree;

        if (isreq && iscdb) {
               proto_tree_add_item(tree, hf_scsi_spc_xcopy_service, tvb, offset, 1, ENC_BIG_ENDIAN);
               serv_action = tvb_get_guint8(tvb, offset) & 0x1F;
               if (cdata) {
                   cdata->itlq->flags = serv_action;
               }
               offset += 1;

               proto_tree_add_item(tree, hf_scsi_reserved_64, tvb, offset, 8, ENC_BIG_ENDIAN);
               offset += 8;
               proto_tree_add_item(tree, hf_scsi_spc_xcopy_param_list_len, tvb, offset, 4, ENC_BIG_ENDIAN);
               /*param_list_len = tvb_get_ntohl(tvb, offset); */
               offset += 4;

               proto_tree_add_item(tree, hf_scsi_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
               offset+= 1;
               proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
                        ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
               /*offset += 1;*/
               /*offset += (param_list_len - 15);*/
        } else {
               if (cdata) {
                        serv_action = cdata->itlq->flags;
               }
               else {
                        return;
               }
               if (serv_action == XCOPY_LID1){
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_list_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_spc_xcopy_param_byte, ett_xcopy_param_byte, xcopy_param_list_bits, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_cscd_desc_list_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                        cscd_desc_list_len = tvb_get_ntohs(tvb, offset);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_reserved_32, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_seg_desc_list_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        seg_desc_list_len = tvb_get_ntohl(tvb, offset);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_inline_data_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        inline_data_len = tvb_get_ntohl(tvb, offset);
                        offset += 4;
                        if (cscd_desc_list_len > 0) {
                                cscds_tree = proto_tree_add_subtree_format(tree, tvb, offset, cscd_desc_list_len, ett_scsi_xcopy_cscds, NULL,
                                                        "CSCD (Copy Source and Copy Destination) descriptors (%u bytes)", cscd_desc_list_len);
                                i = 1;
                                while(cscd_desc_list_len > 0) {
                                        cscd_desc_type = tvb_get_guint8(tvb, offset);
                                        if (cscd_desc_type == 0xEA || cscd_desc_type == 0xEB) { /* both types occupy 64 bytes overall, everything else is 32 bytes */
                                                cscd_tree = proto_tree_add_subtree_format(cscds_tree, tvb, offset, 64, ett_scsi_xcopy_cscd, NULL, "CSCD descriptor #%u", i);
                                        } else {
                                                cscd_tree = proto_tree_add_subtree_format(cscds_tree, tvb, offset, 32, ett_scsi_xcopy_cscd, NULL, "CSCD descriptor #%u", i);
                                        }
                                        i++;
                                        proto_tree_add_item(cscd_tree, hf_scsi_spc_xcopy_cscd_desc_type_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset += 1;
                                        proto_tree_add_bitmask(cscd_tree, tvb, offset, hf_scsi_spc_xcopy_per_dev_type_byte, ett_xcopy_per_dev_type,  per_dev_type_bitmask_fields, ENC_NA);
                                        dev_type = tvb_get_guint8(tvb, offset) & 0x1F;
                                        offset += 1;
                                        proto_tree_add_item(cscd_tree, hf_scsi_spc_xcopy_rel_init_port_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset += 2;
                                        cscd_desc_tree = proto_tree_add_subtree(cscd_tree, tvb, offset, 24, ett_scsi_cscd_desc, NULL, "CSCD descriptor parameters");
                                        proto_tree_add_item(cscd_desc_tree, hf_scsi_spc_xcopy_cscd_desc_code_set, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        code_set = tvb_get_guint8(tvb, offset) & 0x0F;
                                        offset += 1;
                                        proto_tree_add_item(cscd_desc_tree, hf_scsi_spc_xcopy_cscd_desc_assoc, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(cscd_desc_tree, hf_scsi_spc_xcopy_cscd_desc_des_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        des_type = tvb_get_guint8(tvb, offset) & 0x0F;
                                        offset += 1;
                                        proto_tree_add_item(cscd_desc_tree, hf_scsi_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset += 1;
                                        proto_tree_add_item(cscd_desc_tree, hf_scsi_spc_xcopy_cscd_desc_des_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        des_len = tvb_get_guint8(tvb, offset);
                                        offset += 1;
                                        proto_tree_add_bytes_format(cscd_desc_tree, hf_scsi_designator, tvb, offset, 20, NULL, "Designator (20 bytes, zero padded, used length %u)", des_len);
                                        if (code_set == CODESET_BINARY && des_type == DEVID_TYPE_NAA) { /* des_type 3 = NAA */
                                            dissect_naa_designator(cscd_tree, tvb, offset, des_len);
                                        }
                                        offset += 20;
                                        dev_tree = proto_tree_add_subtree(cscd_tree, tvb, offset, 4, ett_scsi_xcopy_dev_params, NULL, "Device type specific parameters");
                                        if (dev_type == BLOCK_DEV_0 || dev_type == BLOCK_DEV_4 || dev_type == BLOCK_DEV_5 || dev_type == BLOCK_DEV_7 || dev_type == BLOCK_DEV_E) {
                                                proto_tree_add_item(dev_tree, hf_scsi_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
                                                offset += 1; /*TODO: dissect this byte */
                                                proto_tree_add_item(dev_tree, hf_scsi_spc_xcopy_disk_block_len, tvb, offset, 3, ENC_BIG_ENDIAN);
                                                offset += 3;
                                        } else {
                                                offset += 4;
                                        }
                                        cscd_desc_list_len -= 32;
                                        if (cscd_desc_type == 0xEA || cscd_desc_type == 0xEB) { /* both types occupy 64 bytes overall, everything else is 32 bytes */
                                                offset += 32;
                                                cscd_desc_list_len -= 32;
                                        }
                                }
                        }
                        if (seg_desc_list_len > 0) {
                                segs_tree = proto_tree_add_subtree_format(tree, tvb, offset, seg_desc_list_len,
                                        ett_scsi_xcopy_segs, NULL, "Segment descriptor list (%u bytes)", seg_desc_list_len);
                                i = 1;
                                while(seg_desc_list_len > 0) {
                                        seg_desc_len = tvb_get_ntohs(tvb, offset + 2);
                                        seg_tree = proto_tree_add_subtree_format(segs_tree, tvb, offset, seg_desc_len + 4,
                                                            ett_scsi_xcopy_seg, NULL, "Segment descriptor #%u", i);
                                        i++;
                                        proto_tree_add_item(seg_tree, hf_scsi_spc_xcopy_seg_desc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        seg_type = tvb_get_guint8(tvb, offset);
                                        offset += 1;
                                        proto_tree_add_item(seg_tree, hf_scsi_spc_xcopy_seg_desc_dc, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(seg_tree, hf_scsi_spc_xcopy_seg_desc_cat, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset += 1;
                                        proto_tree_add_item(seg_tree, hf_scsi_segment_descriptor_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset += 2;
                                        proto_tree_add_item(seg_tree, hf_scsi_spc_xcopy_seg_des_src_desc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset += 2;
                                        proto_tree_add_item(seg_tree, hf_scsi_spc_xcopy_seg_des_dest_desc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset += 2;
                                        seg_param_tree = proto_tree_add_subtree(seg_tree, tvb, offset, seg_desc_len - 4,
                                                            ett_scsi_xcopy_seg_param, NULL, "Segment descriptor parameters");
                                        seg_desc_list_len -= (seg_desc_len + 4);
                                        if (seg_type == BLOCK_TO_BLOCK) {
                                                proto_tree_add_item(seg_param_tree, hf_scsi_reserved_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                                                offset += 2;
                                                proto_tree_add_item(seg_param_tree, hf_scsi_spc_xcopy_num_of_blocks, tvb, offset, 2, ENC_BIG_ENDIAN);
                                                offset += 2;
                                                proto_tree_add_item(seg_param_tree, hf_scsi_spc_xcopy_source_lba, tvb, offset, 8, ENC_BIG_ENDIAN);
                                                offset += 8;
                                                proto_tree_add_item(seg_param_tree, hf_scsi_spc_xcopy_dest_lba, tvb, offset, 8, ENC_BIG_ENDIAN);
                                                offset += 8;
                                        } else {
                                                offset += (seg_desc_len - 4);
                                        }
                                }
                        }
                        if (inline_data_len > 0) {
                                proto_tree_add_item(tree, hf_scsi_inline_data, tvb, offset, inline_data_len, ENC_NA);
                                /*offset += inline_data_len;*/
                        }
              } else if (serv_action == XCOPY_LID4) {
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_param_list_format, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_spc_xcopy_param_byte, ett_xcopy_param_byte, xcopy_param_list_bits, ENC_NA);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_head_cscd_desc_list_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_spc_xcopy_head_cscd_desc_type_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                        /*offset += 1;*/
               }
       }

}

void dissect_spc_recvcopy(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                    proto_tree *tree _U_, guint offset _U_,
                    gboolean isreq _U_, gboolean iscdb _U_,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
        guint16 serv_action;
        guint8  imp_desc_list_len;

        if (isreq && iscdb) {
                proto_tree_add_item(tree, hf_scsi_spc_recv_copy_service, tvb, offset, 1, ENC_BIG_ENDIAN);
                serv_action = tvb_get_guint8(tvb, offset) & 0x1F;
                if (cdata) {
                        cdata->itlq->flags = serv_action;
                }
                offset += 1;
                proto_tree_add_item(tree, hf_scsi_reserved_64, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
                proto_tree_add_item(tree, hf_scsi_alloclen32, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree, hf_scsi_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
                offset += 1;

        } else {
                if (cdata) {
                        serv_action = cdata->itlq->flags;
                }
                else {
                        return;
                }
                if (serv_action == RECV_COPY_PARAMS) {
                        proto_tree_add_item(tree, hf_scsi_recv_copy_avail_data, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_snlid, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_reserved_24, tvb, offset, 3, ENC_BIG_ENDIAN);
                        offset += 3;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_cscd_desc_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_seg_desc_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_desc_list_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_seg_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_inline_data_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_held_data_limit, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_stream_dev_trans_size, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(tree, hf_scsi_reserved_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_total_con_copies, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_max_con_copies, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_data_seg_gran, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_inline_data_gran, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_held_data_gran, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(tree, hf_scsi_reserved_24, tvb, offset, 3, ENC_BIG_ENDIAN);
                        offset += 3;
                        proto_tree_add_item(tree, hf_scsi_recv_copy_implemented_desc_list_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                        imp_desc_list_len = tvb_get_guint8(tvb, offset);
                        offset += 1;
                        while (imp_desc_list_len > 0) {
                                proto_tree_add_item(tree, hf_scsi_spc_xcopy_cscd_desc_type_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset += 1;
                                imp_desc_list_len--;
                        }
                } else {
                        proto_tree_add_expert_format(tree, pinfo, &ei_scsi_unknown_serv_action, tvb, offset, 0, "Unknown serv_action %u", serv_action);
                }
        }
}


static int
dissect_scsi_log_page(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      guint offset)
{
    static const int *pcflags_fields[] = {
        &hf_scsi_log_pagecode,
        NULL
    };
    static const int *paramflags_fields[] = {
        &hf_scsi_log_pf_du,
        &hf_scsi_log_pf_ds,
        &hf_scsi_log_pf_tsd,
        &hf_scsi_log_pf_etc,
        &hf_scsi_log_pf_tmc,
        &hf_scsi_log_pf_lbin,
        &hf_scsi_log_pf_lp,
        NULL
    };
    guint16 pagelen, pagecode;
    guint8 paramlen;
    proto_tree *log_tree;
    proto_item *ti;
    guint old_offset = offset;
    const log_pages_t *log_page;

    pagecode = tvb_get_guint8(tvb, offset) & 0x3f;

    log_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_scsi_log, &ti,
                                "Log Page: %s", val_to_str(pagecode, scsi_log_page_val, "Unknown (0x%04x)"));

    /* page code */
    proto_tree_add_bitmask(log_tree, tvb, offset, hf_scsi_log_pc_flags, ett_scsi_log_pc, pcflags_fields, ENC_BIG_ENDIAN);
    offset+=1;

    /* reserved byte */
    offset+=1;

    /* page length */
    pagelen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(log_tree, hf_scsi_log_page_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;


    /* find the appropriate log page */
    for(log_page = log_pages;log_page;log_page++) {
        if (log_page->parameters == NULL) {
            log_page = NULL;
            break;
        }
        if (log_page->page == pagecode) {
            break;
        }
    }

    /* loop over all parameters */
    while( offset<(old_offset+4+pagelen) ) {
        const log_page_parameters_t *log_parameter = NULL;
        guint16 log_param;

        /* parameter code */
        log_param = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(log_tree, hf_scsi_log_parameter_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* flags */
        proto_tree_add_bitmask(log_tree, tvb, offset, hf_scsi_log_param_flags, ett_scsi_log_param, paramflags_fields, ENC_BIG_ENDIAN);
        offset+=1;

        /* parameter length */
        paramlen = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(log_tree, hf_scsi_log_param_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* find the log parameter */
        if (log_page) {
            for(log_parameter = log_page->parameters;log_parameter;log_parameter++) {
                if (log_parameter->dissector == NULL) {
                    log_parameter = NULL;
                    break;
                }
                if (log_parameter->number == log_param) {
                    break;
                }
            }
        }

        /* parameter data */
        if (paramlen) {
            if (log_parameter && log_parameter->dissector) {
                tvbuff_t *param_tvb;

                param_tvb = tvb_new_subset(tvb, offset, MIN(tvb_reported_length_remaining(tvb, offset),paramlen), paramlen);
                log_parameter->dissector(param_tvb, pinfo, log_tree);
            } else {
                /* We did not have a dissector for this page/parameter so
                 * just display it as data.
                 */
                proto_tree_add_item(log_tree, hf_scsi_log_param_data, tvb, offset, paramlen, ENC_NA);
            }
            offset+=paramlen;
        }
    }

    proto_item_set_len(ti, offset-old_offset);
    return offset;
}

void
dissect_spc_logselect(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *ppcflags_fields[] = {
        &hf_scsi_log_pcr,
        &hf_scsi_log_sp,
        NULL
    };
    static const int *pcflags_fields[] = {
        &hf_scsi_log_pc,
        NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_log_ppc_flags,
                               ett_scsi_log_ppc, ppcflags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_log_pc_flags, ett_scsi_log_pc, pcflags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else {
    }
}

static const true_false_string scsi_log_pcr_tfs = {
    "Reset all parameters to default values",
    "Do not reset log parameters"
};
static const true_false_string scsi_log_ppc_tfs = {
    "Return only parameters that have changed since last LOG SELECT/SENSE",
    "Return parameters even if they are unchanged"
};
static const true_false_string scsi_log_sp_tfs = {
    "Device shall save all log parameters",
    "Device should not save any of the logged parameters"
};

void
dissect_spc_logsense(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *ppcflags_fields[] = {
        &hf_scsi_log_ppc,
        &hf_scsi_log_sp,
        NULL
    };
    static const int *pcflags_fields[] = {
        &hf_scsi_log_pc,
        &hf_scsi_log_pagecode,
        NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_log_ppc_flags,
                               ett_scsi_log_ppc, ppcflags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_log_pc_flags,
                               ett_scsi_log_pc, pcflags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_log_parameter_ptr, tvb, offset+4,
                            2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }
        dissect_scsi_log_page(tvb, pinfo, tree, offset);
    }
}

static void
dissect_scsi_blockdescs(tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *scsi_tree,
                        scsi_task_data_t *cdata, gboolean longlba)
{
    int offset = 0;

    /* without cdata there is no point in continuing */
    if (!cdata)
        return;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        if (longlba) {
            if (tvb_reported_length_remaining(tvb, offset)<8)
                return;
            proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_no_of_blocks64, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;

            if (tvb_reported_length_remaining(tvb, offset)<1)
                return;
            proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_density_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* 3 reserved bytes */
            offset += 3;

            if (tvb_reported_length_remaining(tvb, offset)<4)
                return;
            proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_block_length32, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        } else {
            if ((cdata->itl->cmdset&SCSI_CMDSET_MASK) == SCSI_DEV_SBC) {
                if (tvb_reported_length_remaining(tvb, offset)<4)
                    return;
                proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_no_of_blocks32, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                offset++;  /* reserved */

                if (tvb_reported_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_block_length24, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            } else {
                if (tvb_reported_length_remaining(tvb, offset)<1)
                    return;
                proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_density_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                if (tvb_reported_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_no_of_blocks24, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;

                offset++; /* reserved */

                if (tvb_reported_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_item(scsi_tree, hf_scsi_blockdescs_block_length24, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }
        }
    }
}

static gboolean
dissect_scsi_spc_modepage(tvbuff_t *tvb, packet_info *pinfo _U_,
                          proto_tree *tree, guint offset, guint8 pcode, guint8 spf, guint8 subpcode)
{
    guint8 flags, proto;

    switch (pcode) {
    case SCSI_SPC_MODEPAGE_CTL:
        if (!spf) {
            /* standard page for control */
            proto_tree_add_item(tree, hf_scsi_modesns_tst, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_gltsd, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_report_log_exception_condition, tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_modesns_qmod, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_modesns_qerr, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_disable_queuing, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_modesns_rac, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_modesns_tas, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_swp, tvb, offset+4, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_autoload_mode, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_ready_aer_holdoff_period, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_uint(tree, hf_scsi_spc_modepage_busy_timeout_period, tvb, offset+8, 2,
                                tvb_get_ntohs(tvb, offset+8)*100);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_extended_self_test_completion_time, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        } else {
            switch (subpcode) {
            case 1:
                /* control extension subpage */
                proto_item_append_text(tree, " Control Extension");

                /* TCMOS SCSIP IALUAE */
                proto_tree_add_item(tree, hf_scsi_modepage_tcmos, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_scsi_modepage_scsip, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_scsi_modepage_ialuae, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

                /* Initial Command Priority */
                proto_tree_add_item(tree, hf_scsi_modepage_icp, tvb, offset + 5, 1, ENC_BIG_ENDIAN);

                /* Maximum Sense Data Length */
                proto_tree_add_item(tree, hf_scsi_modepage_msdl, tvb, offset + 6, 1, ENC_BIG_ENDIAN);

                break;
            }
        }
        break;
    case SCSI_SPC_MODEPAGE_DISCON:
        proto_tree_add_item(tree, hf_scsi_spc_modepage_buffer_full_ratio, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_buffer_empty_ratio, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_bus_inactivity_limit, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_disconnect_time_limit, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_connect_time_limit, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_uint(tree, hf_scsi_spc_modepage_maximum_burst_size, tvb, offset+10, 2,
                            tvb_get_ntohs(tvb, offset+10)*512);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_emdp, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_faa, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_fab, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_fac, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_uint(tree, hf_scsi_spc_modepage_first_burst_size, tvb, offset+14, 2,
                            tvb_get_ntohs(tvb, offset+14)*512);
        break;
    case SCSI_SPC_MODEPAGE_INFOEXCP:
        flags = tvb_get_guint8(tvb, offset+2);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_perf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_ebf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_ewasc, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_dexcpt, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_test, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_logerr, tvb, offset+2, 1, ENC_NA);
        if (!((flags & 0x10) >> 4) && ((flags & 0x08) >> 3)) {
            proto_item *hidden_item;
            hidden_item = proto_tree_add_item(tree, hf_scsi_modesns_errrep, tvb,
                                              offset+3, 1, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        else {
            proto_tree_add_item(tree, hf_scsi_modesns_errrep, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(tree, hf_scsi_spc_modepage_interval_timer, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_report_count, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        break;
    case SCSI_SPC_MODEPAGE_PWR:
        proto_tree_add_item(tree, hf_scsi_spc_modepage_idle, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_spc_modepage_standby, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_uint(tree, hf_scsi_spc_modepage_idle_condition_timer, tvb, offset+4, 2,
                            tvb_get_ntohs(tvb, offset+4) * 100);
        proto_tree_add_uint(tree, hf_scsi_spc_modepage_standby_condition_timer, tvb, offset+6, 2,
                            tvb_get_ntohs(tvb, offset+6) * 100);
        break;
    case SCSI_SPC_MODEPAGE_LUN:
        return FALSE;
    case SCSI_SPC_MODEPAGE_PORT:
        proto = tvb_get_guint8(tvb, offset+2) & 0x0F;
        proto_tree_add_item(tree, hf_scsi_protocol, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        if (proto == SCSI_PROTO_FCP) {
            proto_tree_add_item(tree, hf_scsi_spc_modepage_dtfd, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_plpb, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_ddis, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_dlm, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_rha, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_alwi, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_dtipe, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_dtoli, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_rr_tov_units, tvb, offset+6, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_spc_modepage_rr_tov, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        }
        else if (proto == SCSI_PROTO_iSCSI) {
            return FALSE;
        }
        else {
            return FALSE;
        }
        break;
    case SCSI_SCSI2_MODEPAGE_PERDEV:
        return FALSE;
    default:
        return FALSE;
    }
    return TRUE;
}

static gboolean
dissect_scsi_sbc_modepage(tvbuff_t *tvb, packet_info *pinfo _U_,
                          proto_tree *tree, guint offset, guint8 pcode, guint8 spf _U_, guint8 subpcode _U_)
{
    switch (pcode) {
    case SCSI_SBC_MODEPAGE_FMTDEV:
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_tracks_per_zone, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_alternate_sectors_per_zone, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_alternate_tracks_per_zone, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_alternate_tracks_per_lu, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_sectors_per_track, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_data_bytes_per_physical_sector, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_interleave, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_track_skew_factor, tvb, offset+16, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_cylinder_skew_factor, tvb, offset+18, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_ssec, tvb, offset+20, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_hsec, tvb, offset+20, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_rmb, tvb, offset+20, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_surf, tvb, offset+20, 1, ENC_NA);
        break;
    case SCSI_SBC_MODEPAGE_RDWRERR:
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_awre, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_arre, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_tb, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_rc, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_eer, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_per, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_dte, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_dcr, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_read_retry_count, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_correction_span, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_head_offset_count, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_data_strobe_offset_count, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_write_retry_count, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_recovery_time_limit, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        break;
    case SCSI_SBC_MODEPAGE_DISKGEOM:
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_number_of_cylinders, tvb, offset+2, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_number_of_heads, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_starting_cyl_pre_compensation, tvb, offset+6, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_starting_cyl_reduced_write_current, tvb, offset+9, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_device_step_rate, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_landing_zone_cyl, tvb, offset+14, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_rotational_offset, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_medium_rotation_rate, tvb, offset+20, 2, ENC_BIG_ENDIAN);
        break;
    case SCSI_SBC_MODEPAGE_FLEXDISK:
        return FALSE;
    case SCSI_SBC_MODEPAGE_VERERR:
        return FALSE;
    case SCSI_SBC_MODEPAGE_CACHE:
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_ic, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_abpf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_cap, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_disc, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_size, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_wce, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_mf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_rcd, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_demand_read_retention_priority, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_write_retention_priority, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_disable_pre_fetch_xfer_len, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_minimum_pre_fetch, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_maximum_pre_fetch, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_maximum_pre_fetch_ceiling, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_fsw, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_lbcss, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_dra, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_vendor_specific, tvb, offset+12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_number_of_cache_segments, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_cache_segment_size, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_sbc_modepage_non_cache_segment_size, tvb, offset+17, 3, ENC_BIG_ENDIAN);
        break;
    case SCSI_SBC_MODEPAGE_MEDTYPE:
        return FALSE;
    case SCSI_SBC_MODEPAGE_NOTPART:
        return FALSE;
    case SCSI_SBC_MODEPAGE_XORCTL:
        return FALSE;
    default:
        return FALSE;
    }
    return TRUE;
}

static const value_string compression_algorithm_vals[] = {
    {0x00, "No algorithm selected"},
    {0x01, "Default algorithm"},
    {0x03, "IBM ALDC with 512-byte buffer"},
    {0x04, "IBM ALDC with 1024-byte buffer"},
    {0x05, "IBM ALDC with 2048-byte buffer"},
    {0x10, "IBM IDRC"},
    {0x20, "DCLZ"},
    {0xFF, "Unregistered algorithm"},
    {0, NULL}
};

static gboolean
dissect_scsi_ssc2_modepage(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                           proto_tree *tree _U_, guint offset _U_,
                           guint8 pcode, guint8 spf _U_, guint8 subpcode _U_)
{
    switch (pcode) {
    case SCSI_SSC2_MODEPAGE_DATACOMP:
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_dce, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_dcc, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_dde, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_red, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_compression_algorithm, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_decompression_algorithm, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        break;
    case SCSI_SSC2_MODEPAGE_DEVCONF:
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_caf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_active_format, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_active_partition, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_write_object_buffer_full_ratio, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_read_object_buffer_empty_ratio, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(tree, hf_scsi_ssc2_modepage_write_delay_time, tvb, offset+6, 2,
                            tvb_get_ntohs(tvb, offset+6), "%u 100ms",
                            tvb_get_ntohs(tvb, offset+6));
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_obr, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_lois, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_rsmk, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_avc, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_socf, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_robo, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_rew, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_gap_size, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_eod_defined, tvb, offset+10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_eeg, tvb, offset+10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_sew, tvb, offset+10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_swp, tvb, offset+10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_baml, tvb, offset+10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_bam, tvb, offset+10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_object_buffer_size_at_early_warning, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_select_data_compression_algorithm, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_oir, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_rewind_on_reset, tvb, offset+15, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_asocwp, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_perswp, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_prmwp, tvb, offset+15, 1, ENC_NA);
        break;
    case SCSI_SSC2_MODEPAGE_MEDPAR1:
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_maximum_additional_partitions, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_additional_partitions_defined, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_fdp, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_dsp, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_idp, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_psum, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_pofm, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_clear, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_addp, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_media_format_recognition, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_partition_units, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_ssc2_modepage_partition_size, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        break;
    case SCSI_SSC2_MODEPAGE_MEDPAR2:
        return FALSE;
    case SCSI_SSC2_MODEPAGE_MEDPAR3:
        return FALSE;
    case SCSI_SSC2_MODEPAGE_MEDPAR4:
        return FALSE;
    default:
        return FALSE;
    }
    return TRUE;
}

static gboolean
dissect_scsi_mmc5_modepage(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                           proto_tree *tree _U_, guint offset _U_, guint8 pcode, guint8 spf _U_, guint8 subpcode _U_)
{
    guint8  flags;
    guint8  i;

    switch (pcode) {
    case SCSI_MMC5_MODEPAGE_MRW:
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_lba_space, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        break;
    case SCSI_MMC5_MODEPAGE_WRPARAM:
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_bufe, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_ls_v, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_wrparam_test_write, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_write_type, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_wrparam_multi_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_fp, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_copy, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_track_mode, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_data_block_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_link_size, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_initiator_application_code, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_session_format, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_packet_size, tvb, offset+10, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_audio_pause_length, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_media_catalog_number, tvb, offset+16, 16, ENC_NA|ENC_ASCII);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_international_standard_recording_code, tvb, offset+32, 16, ENC_NA|ENC_ASCII);
        for (i = 0; i < 4; i++) {
            flags = tvb_get_guint8(tvb, offset+48+i);
            proto_tree_add_uint_format(tree, hf_scsi_mmc5_modepage_sub_header_byte, tvb, offset+48+i, 1, flags,
                                "Sub-header Byte %u: %u", i, flags);
        }
        if (0x36 == tvb_get_guint8(tvb, offset+1))
            proto_tree_add_item(tree, hf_scsi_mmc5_modepage_vendor_specific, tvb, offset+52, 4, ENC_BIG_ENDIAN);
        break;
    case SCSI_MMC3_MODEPAGE_MMCAP:
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_ram_read, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_r_read, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_rom_read, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_method_2, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_rw_read, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_r_read, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_ram_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_r_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_dvd_rom_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_mmcap_test_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_rw_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_r_write, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_buf, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_mmcap_multi_session, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_mode_2_form2, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_mode_2_form1, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_digital_port2, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_digital_port1, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_composite, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_audio_play, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_read_bar_code, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_upc, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_isrc, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_c2_pointers_supported, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_rw_deinterleaved_corrected, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_rw_supported, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_da_stream_is_accurate, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_cd_da_cmds_supported, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_loading_mechanism_type, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_eject, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_prevent_jumper, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_lock_state, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_lock, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_rw_in_lead_in, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_side_change_capable, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_sw_slot_selection, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_changer_supports_disc_present, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_separate_channel_mute, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_separate_volume_levels, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_number_of_volume_levels_supported, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_buffer_size_supported, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_length, tvb, offset+17, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_lsbf, tvb, offset+17, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_rck, tvb, offset+17, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_bckf, tvb, offset+17, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_copy_management_revision_support, tvb, offset+22, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_rotation_control_selected, tvb, offset+27, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_current_write_speed_selected, tvb, offset+28, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_mmc5_modepage_num_write_speed_performance, tvb, offset+30, 2, ENC_BIG_ENDIAN);
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

static gboolean
dissect_scsi_smc_modepage(tvbuff_t *tvb, packet_info *pinfo _U_,
                          proto_tree *tree, guint offset, guint8 pcode, guint8 spf _U_, guint8 subpcode _U_)
{
    guint8 param_list_len;

    switch (pcode) {
    case SCSI_SMC_MODEPAGE_EAA:
        param_list_len = tvb_get_guint8(tvb, offset+1);
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_first_medium_transport_element_address, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_number_of_medium_transport_elements, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_first_storage_element_address, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_number_of_storage_elements, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_first_import_export_element_address, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_number_of_import_export_elements, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_first_data_transfer_element_address, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_item(tree, hf_scsi_smc_modepage_number_of_data_transfer_elements, tvb, offset+16, 2, ENC_BIG_ENDIAN);
        break;
    case SCSI_SMC_MODEPAGE_TRANGEOM:
        return FALSE;
    case SCSI_SMC_MODEPAGE_DEVCAP:
        proto_tree_add_item(tree, hf_scsi_smc_modepage_stordt, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_storie, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_storst, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_stormt, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_dt, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_ie, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_st, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_mt, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_dt, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_ie, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_st, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_mt, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_dt, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_ie, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_st, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_mt, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_dt, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_ie, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_st, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_mt, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_ne_dt, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_ne_ie, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_ne_st, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_mt_ne_mt, tvb, offset+12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_ne_dt, tvb, offset+13, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_ne_ie, tvb, offset+13, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_ne_st, tvb, offset+13, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_st_ne_mt, tvb, offset+13, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_ne_dt, tvb, offset+14, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_ne_ie, tvb, offset+14, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_ne_st, tvb, offset+14, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_ie_ne_mt, tvb, offset+14, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_ne_dt, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_ne_ie, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_ne_st, tvb, offset+15, 1, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_smc_modepage_dt_ne_mt, tvb, offset+15, 1, ENC_NA);
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

static guint
dissect_scsi_modepage(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *scsi_tree, guint offset,
                      scsi_device_type devtype)
{
    guint16             plen;
    guint8              pcode, spf, subpcode = 0;
    proto_tree         *tree;
    const value_string *modepage_val;
    int                 hf_pagecode;
    gboolean (*dissect_modepage)(tvbuff_t *, packet_info *, proto_tree *,
                                 guint, guint8, guint8, guint8);

    pcode = tvb_get_guint8(tvb, offset) & SCSI_MS_PCODE_BITS;
    spf   = tvb_get_guint8(tvb, offset) & 0x40;
    if (spf) {
        subpcode = tvb_get_guint8(tvb, offset + 1);
        plen = tvb_get_ntohs(tvb, offset + 2);
    } else {
        plen = tvb_get_guint8(tvb, offset + 1);
    }

    if (try_val_to_str(pcode & SCSI_MS_PCODE_BITS,
                     scsi_spc_modepage_val) == NULL) {
        /*
         * This isn't a generic mode page that applies to all SCSI
         * device types; try to interpret it based on what we deduced,
         * or were told, the device type is.
         */
        switch (devtype) {
        case SCSI_DEV_SBC:
            modepage_val = scsi_sbc_modepage_val;
            hf_pagecode = hf_scsi_sbcpagecode;
            dissect_modepage = dissect_scsi_sbc_modepage;
            break;

        case SCSI_DEV_SSC:
            modepage_val = scsi_ssc2_modepage_val;
            hf_pagecode = hf_scsi_sscpagecode;
            dissect_modepage = dissect_scsi_ssc2_modepage;
            break;

        case SCSI_DEV_SMC:
            modepage_val = scsi_smc_modepage_val;
            hf_pagecode = hf_scsi_smcpagecode;
            dissect_modepage = dissect_scsi_smc_modepage;
            break;

        case SCSI_DEV_CDROM:
            modepage_val = scsi_mmc5_modepage_val;
            hf_pagecode = hf_scsi_mmcpagecode;
            dissect_modepage = dissect_scsi_mmc5_modepage;
            break;

        default:
            /*
             * The "val_to_str()" lookup will fail in this table
             * (it failed in "try_val_to_str()"), so it'll return
             * "Unknown (XXX)", which is what we want.
             */
            modepage_val = scsi_spc_modepage_val;
            hf_pagecode = hf_scsi_spc_pagecode;
            dissect_modepage = dissect_scsi_spc_modepage;
            break;
        }
    } else {
        modepage_val = scsi_spc_modepage_val;
        hf_pagecode = hf_scsi_spc_pagecode;
        dissect_modepage = dissect_scsi_spc_modepage;
    }

    tree = proto_tree_add_subtree_format(scsi_tree, tvb, offset, plen + (spf ? 4 : 2),
                             ett_scsi_page, NULL, "%s Mode Page",
                             val_to_str(pcode & SCSI_MS_PCODE_BITS,
                                        modepage_val, "Unknown (0x%08x)"));
    proto_tree_add_item(tree, hf_scsi_modepage_ps, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_modepage_spf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pagecode, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (spf) {
        proto_tree_add_item(tree, hf_scsi_spc_subpagecode, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_modepage_plen, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_scsi_modepage_plen, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    }

    if (!tvb_bytes_exist(tvb, offset, plen)) {
        /* XXX - why not just drive on and throw an exception? */
        return (plen + 2);
    }

    if (!(*dissect_modepage)(tvb, pinfo, tree, offset,
                             pcode, spf, subpcode)) {
        proto_tree_add_expert(tree, pinfo, &ei_scsi_unknown_page, tvb, offset+2, plen);
    }
    return (plen+2);
}

void
dissect_spc_modeselect6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len, scsi_task_data_t *cdata)
{
    guint8    flags;
    guint     plen;
    gint      desclen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_modesel_flags, tvb, offset, 1,
                                   flags, "PF = %u, SP = %u", flags & 0x10,
                                   flags & 0x1);
        proto_tree_add_item(tree, hf_scsi_paramlen, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else {
        /* Mode Parameter has the following format:
         * Mode Parameter Header
         *    - Mode Data Len, Medium Type, Dev Specific Parameter,
         *      Blk Desc Len
         * Block Descriptor (s)
         *    - Number of blocks, density code, block length
         * Page (s)
         *    - Page code, Page length, Page Parameters
         */
        if (payload_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_mode_data_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        payload_len -= 1;
        /* The mode data length is reserved for MODE SELECT, so we just
           use the payload length. */

        if (payload_len < 1)
            return;
        switch (cdata->itl->cmdset&SCSI_CMDSET_MASK) {

        case SCSI_DEV_SBC:
            proto_tree_add_item(tree, hf_scsi_modesel_dev_sbc_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        default:
            proto_tree_add_item(tree, hf_scsi_modesel_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        }
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_device_specific_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        desclen = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_block_descriptor_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        payload_len -= 1;

        if (tvb_reported_length_remaining(tvb, offset)>0) {
            blockdesc_tvb = tvb_new_subset(tvb, offset, MIN(tvb_reported_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs(blockdesc_tvb, pinfo, tree, cdata, FALSE);
        }
        offset += desclen;
        payload_len -= desclen;

        /* offset points to the start of the mode page */
        while ((payload_len > 0) && tvb_bytes_exist(tvb, offset, 2)) {
            plen = dissect_scsi_modepage(tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            payload_len -= plen;
        }
    }
}

void
dissect_spc_modeselect10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len, scsi_task_data_t *cdata)
{
    guint8    flags;
    gboolean  longlba;
    gint      desclen;
    guint     plen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_modesel_flags, tvb, offset, 1,
                                   flags, "PF = %u, SP = %u", flags & 0x10,
                                   flags & 0x1);
        proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else {
        /* Mode Parameter has the following format:
         * Mode Parameter Header
         *    - Mode Data Len, Medium Type, Dev Specific Parameter,
         *      Blk Desc Len
         * Block Descriptor (s)
         *    - Number of blocks, density code, block length
         * Page (s)
         *    - Page code, Page length, Page Parameters
         */
        if (payload_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_mode_data_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        payload_len -= 2;
        /* The mode data length is reserved for MODE SELECT, so we just
           use the payload length. */

        if (payload_len < 1)
            return;
        if (!cdata->itl)
            return;
        switch (cdata->itl->cmdset&SCSI_CMDSET_MASK) {

        case SCSI_DEV_SBC:
            proto_tree_add_item(tree, hf_scsi_modesel_dev_sbc_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        default:
            proto_tree_add_item(tree, hf_scsi_modesel_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        }
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_device_specific_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        longlba = tvb_get_guint8(tvb, offset) & 0x1;
        proto_tree_add_item(tree, hf_scsi_modesel_longlba, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;    /* skip LongLBA byte and reserved byte */
        payload_len -= 2;

        if (payload_len < 1)
            return;
        desclen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_block_descriptor_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        payload_len -= 2;

        if (tvb_reported_length_remaining(tvb, offset)>0) {
            blockdesc_tvb = tvb_new_subset(tvb, offset, MIN(tvb_reported_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs(blockdesc_tvb, pinfo, tree, cdata, longlba);
        }
        offset += desclen;
        payload_len -= desclen;

        /* offset points to the start of the mode page */
        while ((payload_len > 0) && tvb_bytes_exist(tvb, offset, 2)) {
            plen = dissect_scsi_modepage(tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            payload_len -= plen;
        }
    }
}

static void
dissect_scsi_pagecode(tvbuff_t *tvb, packet_info *pinfo _U_,
                      proto_tree *tree, guint offset,
                      scsi_task_data_t *cdata)
{
    guint8 pcode;
    int    hf_pagecode;

    /* unless we have cdata there is not much point in continuing */
    if (!cdata)
        return;

    pcode = tvb_get_guint8(tvb, offset);
    if (try_val_to_str(pcode & SCSI_MS_PCODE_BITS,
                     scsi_spc_modepage_val) == NULL) {
        /*
         * This isn't a generic mode page that applies to all SCSI
         * device types; try to interpret it based on what we deduced,
         * or were told, the device type is.
         */
        switch (cdata->itl->cmdset&SCSI_CMDSET_MASK) {
        case SCSI_DEV_SBC:
            hf_pagecode = hf_scsi_sbcpagecode;
            break;

        case SCSI_DEV_SSC:
            hf_pagecode = hf_scsi_sscpagecode;
            break;

        case SCSI_DEV_SMC:
            hf_pagecode = hf_scsi_smcpagecode;
            break;

        case SCSI_DEV_CDROM:
            hf_pagecode = hf_scsi_mmcpagecode;
            break;

        default:
            hf_pagecode = hf_scsi_spc_pagecode;
            break;
        }
    } else {
        hf_pagecode = hf_scsi_spc_pagecode;
    }
    proto_tree_add_uint(tree, hf_pagecode, tvb, offset, 1, pcode);
}

void
dissect_spc_modesense6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len, scsi_task_data_t *cdata)
{
    guint8    flags;
    guint     plen;
    gint      tot_len, desclen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                   flags, "DBD = %u", flags & 0x8);
        proto_tree_add_item(tree, hf_scsi_modesns_pc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        dissect_scsi_pagecode(tvb, pinfo, tree, offset+1, cdata);
        proto_tree_add_item(tree, hf_scsi_alloclen, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else {
        /* Mode sense response has the following format:
         * Mode Parameter Header
         *    - Mode Data Len, Medium Type, Dev Specific Parameter,
         *      Blk Desc Len
         * Block Descriptor (s)
         *    - Number of blocks, density code, block length
         * Page (s)
         *    - Page code, Page length, Page Parameters
         */
        tot_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_mode_data_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* The actual payload is the min of the length in the response & the
         * space allocated by the initiator as specified in the request.
         *
         * XXX - the payload length includes the length field, so we
         * really should subtract the length of the length field from
         * the payload length - but can it really be zero here?
         */
        if (payload_len && (tot_len > (gint)payload_len))
            tot_len = payload_len;

        if (tot_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_device_specific_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        desclen = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_block_descriptor_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tot_len -= 1;


        if (tvb_reported_length_remaining(tvb, offset)>0) {
            blockdesc_tvb = tvb_new_subset(tvb, offset, MIN(tvb_reported_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs(blockdesc_tvb, pinfo, tree, cdata, FALSE);
        }
        offset += desclen;
        tot_len -= desclen;

        /* offset points to the start of the mode page */
        while ((tot_len > 0) && tvb_bytes_exist(tvb, offset, 2)) {
            plen = dissect_scsi_modepage(tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
dissect_spc_modesense10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len, scsi_task_data_t *cdata)
{
    guint8    flags;
    gboolean  longlba;
    gint      tot_len, desclen;
    guint     plen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                   flags, "LLBAA = %u, DBD = %u", flags & 0x10,
                                   flags & 0x8);
        proto_tree_add_item(tree, hf_scsi_modesns_pc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        dissect_scsi_pagecode(tvb, pinfo, tree, offset+1, cdata);
        proto_tree_add_item(tree, hf_scsi_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    else {
        /* Mode sense response has the following format:
         * Mode Parameter Header
         *    - Mode Data Len, Medium Type, Dev Specific Parameter,
         *      Blk Desc Len
         * Block Descriptor (s)
         *    - Number of blocks, density code, block length
         * Page (s)
         *    - Page code, Page length, Page Parameters
         */
        tot_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_mode_data_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* The actual payload is the min of the length in the response & the
         * space allocated by the initiator as specified in the request.
         *
         * XXX - the payload length includes the length field, so we
         * really should subtract the length of the length field from
         * the payload length - but can it really be zero here?
         */
        if (payload_len && (tot_len > (gint)payload_len))
            tot_len = payload_len;

        if (tot_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_medium_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        proto_tree_add_item(tree, hf_scsi_modesel_device_specific_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        longlba = tvb_get_guint8(tvb, offset) & 0x1;
        proto_tree_add_item(tree, hf_scsi_modesel_longlba, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;    /* skip LongLBA byte and reserved byte */
        tot_len -= 2;

        if (tot_len < 2)
            return;
        desclen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_modesel_block_descriptor_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        tot_len -= 2;

        if (tvb_reported_length_remaining(tvb, offset)>0) {
            blockdesc_tvb = tvb_new_subset(tvb, offset, MIN(tvb_reported_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs(blockdesc_tvb, pinfo, tree, cdata, longlba);
        }
        offset += desclen;
        tot_len -= desclen;

        /* offset points to the start of the mode page */
        while ((tot_len > 0) && tvb_bytes_exist(tvb, offset, 2)) {
            plen = dissect_scsi_modepage(tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
dissect_spc_preventallowmediaremoval(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                     guint offset, gboolean isreq, gboolean iscdb,
                                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (isreq && iscdb) {
        static const int *prevent_allow_fields[] = {
            &hf_scsi_prevent_allow_prevent,
            NULL
        };
        guint8 flags;

        proto_tree_add_bitmask(tree, tvb, offset + 3, hf_scsi_prevent_allow_flags,
            ett_scsi_prevent_allow, prevent_allow_fields, ENC_BIG_ENDIAN);

        flags = tvb_get_guint8(tvb, offset + 3);
        if (flags & 0x01) {
            col_append_str(pinfo->cinfo, COL_INFO, " PREVENT");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, " ALLOW");
        }

        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_spc_persistentreservein(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                guint offset, gboolean isreq, gboolean iscdb,
                                guint payload_len, scsi_task_data_t *cdata)
{
    guint16 flags;
    int     numrec, i;
    guint   len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item(tree, hf_scsi_persresvin_svcaction, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
        /* We store the service action since we want to interpret the data */
        cdata->itlq->flags = tvb_get_guint8(tvb, offset);
    }
    else {
        if (cdata) {
            flags = cdata->itlq->flags;
        }
        else {
            flags = 0xFF;
        }
        proto_tree_add_item(tree, hf_scsi_persresvin_generation_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        len = tvb_get_ntohl(tvb, offset+4);
        proto_tree_add_item(tree, hf_scsi_persresvin_additional_length, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        len = (payload_len > len) ? len : payload_len;

        if ((flags & 0x1F) == SCSI_SPC_RESVIN_SVCA_RDKEYS) {
            /* XXX - what if len is < 8?  That may be illegal, but
               that doesn't make it impossible.... */
            numrec = len / 8;
            offset += 8;

            for (i = 0; i < numrec; i++) {
                proto_tree_add_item(tree, hf_scsi_persresv_key, tvb, offset,
                                    8, ENC_NA);
                offset += 8;
            }
        }
        else if ((flags & 0x1F) == SCSI_SPC_RESVIN_SVCA_RDRESV && len) {
            proto_tree_add_item(tree, hf_scsi_persresv_key, tvb, offset+8,
                                8, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_persresv_scopeaddr, tvb,
                                offset+16, 4, ENC_NA);
            proto_tree_add_item(tree, hf_scsi_persresv_scope, tvb, offset+21,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_persresv_type, tvb, offset+21,
                                1, ENC_BIG_ENDIAN);
        }
    }
}

void
dissect_spc_persistentreserveout(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                 guint offset, gboolean isreq, gboolean iscdb,
                                 guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 svcaction;

    if (!tree)
        return;

    if (isreq && iscdb) {
        svcaction = tvb_get_guint8(tvb, offset) & 0x1F;
        proto_tree_add_item(tree, hf_scsi_persresvout_svcaction, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* type and scope are ignored for REGISTER, REGISTER AND IGNORE EXISTING KEY, CLEAR service actions */
        if (svcaction != SCSI_PR_REGISTER && svcaction != SCSI_PR_REG_IGNORE && svcaction != SCSI_PR_CLEAR) {
            proto_tree_add_item(tree, hf_scsi_persresv_scope, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_persresv_type, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
        /* We store the service action since we want to interpret the params */
        cdata->itlq->flags = tvb_get_guint8(tvb, offset);
    }
    else if (isreq && !iscdb) {
        proto_tree_add_item(tree, hf_scsi_persresvout_reskey, tvb, offset,
                            8, ENC_NA);
        proto_tree_add_item(tree, hf_scsi_persresvout_sareskey, tvb,
                            offset +8, 8, ENC_NA);
        if (cdata->itlq->flags == 0x07) {
            /* Service action REGISTER AND MOVE */
            const int *persresv_fields[] = {
                &hf_scsi_persresv_control_rsvd,
                &hf_scsi_persresv_control_unreg,
                &hf_scsi_persresv_control_aptpl,
                NULL
            };
            guint32 tid_len = tvb_get_ntohl(tvb, offset+20);

            proto_tree_add_item(tree, hf_scsi_persresvout_obsolete, tvb,
                                offset+16, 1, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, offset+17,
                                   hf_scsi_persresvout_control, ett_persresv_control,
                                   persresv_fields, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_persresvout_rel_tpi, tvb,
                                offset+18, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_persresvout_transportid_len, tvb,
                                offset+20, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_persresvout_transportid, tvb,
                                offset+24, tid_len, ENC_NA);
        }
        else {
            /* Other service actions than REGISTER AND MOVE. */
            const int *persresv_fields[] = {
                &hf_scsi_persresv_control_rsvd1,
                &hf_scsi_persresv_control_spec_i_pt,
                &hf_scsi_persresv_control_all_tg_pt,
                &hf_scsi_persresv_control_rsvd2,
                &hf_scsi_persresv_control_aptpl,
                NULL
            };

            proto_tree_add_item(tree, hf_scsi_persresvout_obsolete, tvb,
                                offset+16, 4, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, offset+20,
                                   hf_scsi_persresvout_control, ett_persresv_control,
                                   persresv_fields, ENC_BIG_ENDIAN);
        }
    }
    else {
    }
}

void
dissect_spc_release6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_spc_release10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_release_flags, tvb, offset, 1,
                                   flags,
                                   "Flags: 3rd Party ID = %u, LongID = %u",
                                   flags & 0x10, flags & 0x2);
        if ((flags & 0x12) == 0x10) {
            proto_tree_add_item(tree, hf_scsi_release_thirdpartyid, tvb,
                                offset+2, 1, ENC_NA);
        }
        proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_spc_reportdeviceidentifier(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                                   proto_tree *tree _U_,
                                   guint offset _U_, gboolean isreq _U_, gboolean iscdb _U_,
                                   guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

void
dissect_scsi_lun(proto_tree *tree, tvbuff_t *tvb, guint offset) {
    proto_item *ti;
    proto_tree *tt, *tl = proto_tree_add_subtree(tree, tvb, offset, 8, ett_scsi_lun, &ti, "LUN");
    guint8 address_mode, lun_len = 0, ea_code = 0, len_code = 0, lun_count = 0, complex_lun = 0;
    guint16 lun = 0;
    const gchar *str = NULL;

    if (tvb_get_ntoh48(tvb, offset) << 16) {
        /* Pedantically change LUN to LUNs */
        proto_item_append_text(tl, "s");
        complex_lun = 1;
    }

    while (lun_len < 8) {
        lun = tvb_get_ntohs(tvb, offset + lun_len);
        /* Don't skip the first non-zero LUN */
        if (lun_len && !lun)
            break;

        address_mode = tvb_get_guint8(tvb, offset + lun_len);
        if ((address_mode >> 6) < 0x3)
            len_code = 2;
        else {
            len_code = (address_mode & 0x30) >> 4;
            len_code = 2 + (len_code * 2);
        }

        if (complex_lun) {
            /* Add lun subtrees only for complex luns */
            tt = proto_tree_add_subtree(tl, tvb, offset + lun_len, len_code, ett_scsi_lun_unit, &ti, "LUN");
            proto_item_append_text(tt, " %d", lun_count++);
        } else
            tt = tl;

        /* Peripheral and Simple logical unit addressing share the same identifier, with bus defining the difference */
        if (!address_mode)
            proto_tree_add_uint_format_value(tt, hf_scsi_lun_address_mode, tvb, offset + lun_len, 1, (address_mode >> 6),
                                             "Simple logical unit addressing (0x0%x)", address_mode >> 6);
        else
            proto_tree_add_item(tt, hf_scsi_lun_address_mode, tvb, offset + lun_len, 1, ENC_BIG_ENDIAN);

        switch (address_mode >> 6) {
        case 0:
            /*  Simple logical unit addressing method has no bus id */
            if (address_mode) {
                proto_tree_add_bits_item(tt, hf_scsi_bus, tvb, (offset + lun_len) * 8 + 2, 0x6, ENC_BIG_ENDIAN);
                lun = tvb_get_guint8(tvb, offset + lun_len + 1);
                proto_tree_add_uint(tt, hf_scsi_lun, tvb, offset + lun_len + 1, 1, lun);
            } else {
                proto_tree_add_bits_item(tt, hf_scsi_lun, tvb, (offset + lun_len) * 8 + 2, 0xe, ENC_BIG_ENDIAN);
            }
            lun_len += len_code;
            break;

        case 1:
            proto_tree_add_bits_item(tt, hf_scsi_lun, tvb, (offset + lun_len) * 8 + 2, 0xe, ENC_BIG_ENDIAN);
            lun_len += len_code;
            break;
        case 2:
            proto_tree_add_item(tt, hf_scsi_target, tvb, offset + lun_len, 1, ENC_BIG_ENDIAN);
            proto_tree_add_bits_item(tt, hf_scsi_bus, tvb, (offset + lun_len + 1) * 8, 0x3, ENC_BIG_ENDIAN);
            proto_tree_add_bits_item(tt, hf_scsi_lun, tvb, (offset + lun_len + 1) * 8 + 3, 0x5, ENC_BIG_ENDIAN);
            lun_len += len_code;
            break;
        case 3:
            ea_code = address_mode & 0xf;
            lun = len_code;
            len_code = (address_mode & 0x30) >> 4;

            ti = proto_tree_add_item(tt, hf_scsi_extended_add_method_len, tvb, offset + lun_len, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " (%d bytes)", lun);

            ti = proto_tree_add_item(tt, hf_scsi_extended_add_method, tvb, offset + lun_len, 1, ENC_BIG_ENDIAN);

            str = NULL;
            switch(ea_code) {
            case 0x1:
                if (!len_code) {
                    str = "Well known logical unit";
                    proto_tree_add_item(tt, hf_scsi_lun, tvb, offset + lun_len + 1, 1, ENC_BIG_ENDIAN);
                }
                break;
            case 0x2:
                if (len_code == 0x1)
                    str = "Extended flat space addressing";
                else if (len_code == 0x2)
                    str = "Long extended flat space addressing";
                if (str)
                    proto_tree_add_item(tt, hf_scsi_lun_extended, tvb, offset + lun_len + 1, lun - 1, ENC_BIG_ENDIAN);
                break;
            case 0xe:
                if (len_code == 0x3)
                    str = "Reserved for FC-SB-5";
                break;
            case 0xf:
                /* The contents of all hierarchical LUN structure addressing fields following a logical unit not specified addressing
                 * method addressing field shall be ignored. [SAM5] 4.7.7.5.4 */
                if (len_code == 0x3) {
                    proto_item_append_text(ti, " (Logical unit not specified)");
                    return;
                }
                break;
            default:
                str = "Reserved";
                break;
            }

            len_code = (guint8)lun;
            if (!str)
                str = "Reserved";

            proto_item_append_text(ti, " (%s)", str);
            lun_len += len_code;
            break;

        default:
            break;
        }
    }
}

void
dissect_spc_reportluns(tvbuff_t *tvb_a, packet_info *pinfo _U_,
                       proto_tree *tree, guint offset_a,
                       gboolean isreq, gboolean iscdb, guint payload_len _U_,
                       scsi_task_data_t *cdata _U_)
{
    gint               listlen;

    if (isreq && iscdb) {
        proto_tree_add_item(tree, hf_scsi_select_report, tvb_a, offset_a+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_alloclen32, tvb_a, offset_a+5, 4, ENC_BIG_ENDIAN);
        if (cdata) {
            cdata->itlq->alloc_len = tvb_get_ntohl(tvb_a, offset_a+5);
        }
        proto_tree_add_bitmask(tree, tvb_a, offset_a+10, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }

        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */
        listlen = tvb_get_ntohl(try_tvb, try_offset);
        proto_tree_add_item(tree, hf_scsi_reportluns_lun_list_length, try_tvb, try_offset, 4, ENC_BIG_ENDIAN);
        try_offset += 8;

        while(listlen>0) {
            dissect_scsi_lun(tree, try_tvb, try_offset);
            try_offset+=8;
            listlen-=8;
        }
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

const value_string mpi_action_vals[] = {
    {MPI_MANAGEMENT_PROTOCOL_IN           , "Management Protocol In"},
    {MPI_REPORT_SUPPORTED_OPERATION_CODES , "Report Supported Opcodes"},
    {0, NULL}
};

const value_string report_opcodes_options_vals[] = {
    {0, "Report ALL opcodes"},
    {1, "Report ONE opcode, NO service action"},
    {2, "Report ONE opcode, WITH service action"},
    {0, NULL}
};

void
dissect_spc_mgmt_protocol_in(tvbuff_t *tvb_a, packet_info *pinfo _U_,
                 proto_tree *tree, guint offset_a,
                 gboolean isreq, gboolean iscdb,
                 guint payload_len _U_,
                 scsi_task_data_t *cdata _U_)
{
    guint8             service_action;

    if (isreq && iscdb) {
        service_action = tvb_get_guint8 (tvb_a, offset_a) & 0x1F;
    if (cdata) {
        cdata->itlq->flags=service_action;
    }
    col_append_str(pinfo->cinfo, COL_INFO,
            val_to_str(service_action, mpi_action_vals, "Unknown"));

    proto_tree_add_item(tree, hf_scsi_mpi_service_action, tvb_a,
            offset_a, 1, ENC_BIG_ENDIAN);

    switch(service_action){
        case MPI_REPORT_SUPPORTED_OPERATION_CODES:
            proto_tree_add_item(tree, hf_scsi_report_opcodes_rctd,
                    tvb_a, offset_a+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_report_opcodes_options,
                    tvb_a, offset_a+1, 1, ENC_BIG_ENDIAN);
            if (cdata && (tvb_get_guint8(tvb_a, offset_a+1) & 0x07)) {
                /* Need the one-command parameter format */
                cdata->itlq->flags|=0x80;
            }

            proto_tree_add_item(tree, hf_scsi_report_opcodes_requested_o,
                    tvb_a, offset_a+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_scsi_report_opcodes_requested_sa,
                    tvb_a, offset_a+3, 2, ENC_BIG_ENDIAN);

            proto_tree_add_item(tree, hf_scsi_alloclen32, tvb_a,
                    offset_a+5, 4, ENC_BIG_ENDIAN);
            if (cdata) {
                cdata->itlq->alloc_len = tvb_get_ntohl(tvb_a, offset_a+5);
            }
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_scsi_no_dissection_for_service_action, tvb_a, offset_a+1, 8);
    }

    proto_tree_add_bitmask(tree, tvb_a, offset_a+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);

    } else if (!isreq) {
        proto_item *it;
        int length;
        cmdset_t *csdata;
        int ctdp;

        if (!cdata || !cdata->itlq || !cdata->itl) {
            return;
        }

        csdata = get_cmdset_data(cdata->itlq, cdata->itl);

        it = proto_tree_add_uint(tree, hf_scsi_mpi_service_action, tvb_a, 0, 0, cdata->itlq->flags & 0x7f);
        PROTO_ITEM_SET_GENERATED(it);

        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */

        switch (cdata->itlq->flags & 0x7f) {
            case MPI_REPORT_SUPPORTED_OPERATION_CODES:
                if (cdata->itlq->flags & 0x80) {
                    /* one-command format */
                    proto_tree_add_item(tree, hf_scsi_report_opcodes_ctdp_one,
                            try_tvb, try_offset+1, 1, ENC_BIG_ENDIAN);
                    ctdp = tvb_get_guint8(try_tvb, try_offset+1) & 0x80;

                    proto_tree_add_item(tree, hf_scsi_report_opcodes_support,
                            try_tvb, try_offset+1, 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_scsi_report_opcodes_cdb_length,
                            try_tvb, try_offset+2, 2, ENC_BIG_ENDIAN);
                    length = tvb_get_ntohs(try_tvb, try_offset+2);

                    proto_tree_add_item(tree, hf_scsi_report_opcodes_cdb_usage_data,
                            try_tvb, try_offset+4, length, ENC_NA);

                    if (ctdp) {
                        proto_tree *tr;

                        tr = proto_tree_add_subtree(tree, try_tvb, try_offset,
                                12, ett_timeout_descriptor, NULL, "Timeout Descriptor");

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_tdl,
                                try_tvb, try_offset, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_npt,
                                try_tvb, try_offset + 4, 4, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_rct,
                                try_tvb, try_offset + 8, 4, ENC_BIG_ENDIAN);
                    }
                } else {
                    /* all commands format */
                    proto_tree_add_item(tree, hf_scsi_report_opcodes_cdl,
                            try_tvb, try_offset+0, 4, ENC_BIG_ENDIAN);
                    length = tvb_get_ntohl(try_tvb, try_offset);
                    try_offset += 4;

                    while (length >= 20) {
                        proto_tree *tr;

                        tr = proto_tree_add_subtree_format(tree, try_tvb, try_offset,
                                20, ett_command_descriptor, NULL, "Command Descriptor: %s",
                                val_to_str_ext_const(tvb_get_guint8(try_tvb, try_offset+0), csdata->cdb_vals_ext, "Unknown"));

                        proto_tree_add_item(tr, csdata->hf_opcode,
                                try_tvb, try_offset+0, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_sa,
                                try_tvb, try_offset+2, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_ctdp,
                                try_tvb, try_offset+5, 1, ENC_BIG_ENDIAN);
                        ctdp = tvb_get_guint8(try_tvb, try_offset+5) & 0x02;

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_servactv,
                                try_tvb, try_offset+5, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_cdb_length,
                                try_tvb, try_offset+6, 2, ENC_BIG_ENDIAN);

                        try_offset += 8;
                        length -= 8;

                        if (!ctdp) {
                            continue;
                        }

                        tr = proto_tree_add_subtree(tree, try_tvb, try_offset,
                                12, ett_timeout_descriptor, NULL, "Timeout Descriptor");

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_tdl,
                                try_tvb, try_offset, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_npt,
                                try_tvb, try_offset + 4, 4, ENC_BIG_ENDIAN);

                        proto_tree_add_item(tr, hf_scsi_report_opcodes_rct,
                                try_tvb, try_offset + 8, 4, ENC_BIG_ENDIAN);

                        try_offset += 12;
                        length -= 12;

                    }
                }
                break;
            default:
                proto_tree_add_expert(tree, pinfo, &ei_scsi_no_dissection_for_service_action, try_tvb, try_offset+1, 8);
        }

        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

static void
dissect_scsi_sns_specific_info(tvbuff_t *tvb, proto_tree *sns_tree, guint offset, guint8 sense_key) {
 guint8 valid = tvb_get_guint8(tvb, offset)&0x80;
 proto_tree_add_item(sns_tree, hf_scsi_sksv, tvb, offset, 1, ENC_BIG_ENDIAN);
 proto_tree_add_item(sns_tree, hf_scsi_sks_info, tvb, offset, 3, ENC_BIG_ENDIAN);

 if (sense_key==5&&valid) {
    /*illegal request*/
    proto_tree_add_item(sns_tree, hf_scsi_sks_fp_cd, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_sks_fp_bpv, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_sks_fp_bit, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_sks_fp_field,  tvb, offset, 3, ENC_BIG_ENDIAN);
 }
}

static void
dissect_scsi_fix_snsinfo(tvbuff_t *tvb, proto_tree *sns_tree, guint offset) {
    proto_item *hidden_item;
    guint8      flags;

    proto_tree_add_item(sns_tree, hf_scsi_sns_valid, tvb, offset, 1, ENC_BIG_ENDIAN);

    flags = tvb_get_guint8(tvb, offset+2);
    proto_tree_add_item(sns_tree, hf_scsi_sns_filemark, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(sns_tree, hf_scsi_sns_eom, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(sns_tree, hf_scsi_sns_ili, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(sns_tree, hf_scsi_snskey, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_snsinfo, tvb, offset+3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_addlsnslen, tvb, offset+7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_sns_command_specific_information, tvb, offset+8, 4, ENC_NA);
    proto_tree_add_item(sns_tree, hf_scsi_ascascq, tvb, offset+12, 2, ENC_BIG_ENDIAN);
    hidden_item = proto_tree_add_item(sns_tree, hf_scsi_asc, tvb, offset+12, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(sns_tree, hf_scsi_ascq, tvb, offset+13, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_item(sns_tree, hf_scsi_fru, tvb, offset+14, 1, ENC_BIG_ENDIAN);
    dissect_scsi_sns_specific_info(tvb,sns_tree,offset+15,flags&0x0F);
}

static void
dissect_scsi_descriptor_snsinfo(tvbuff_t *tvb, proto_tree *sns_tree, guint offset)
{
    guint8  additional_length, sense_key;
    guint   end;

    proto_tree_add_item(sns_tree, hf_scsi_snskey, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_ascascq, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sns_tree, hf_scsi_addlsnslen, tvb, offset+7, 1, ENC_BIG_ENDIAN);
    sense_key = tvb_get_guint8(tvb, offset+1)&0xF;
    additional_length = tvb_get_guint8(tvb, offset+7);
    end = offset+7+additional_length;
    offset+=8;
    while (offset<end-2) {
       guint8      desc_type, desc_length, desc_end;
       proto_item *item;
       proto_tree *desc_tree;

       desc_type   = tvb_get_guint8(tvb, offset);
       desc_length = tvb_get_guint8(tvb, offset+1);
       desc_end    = offset+desc_length+2;
       desc_tree = proto_tree_add_subtree(sns_tree, tvb, offset, desc_length+2, ett_sense_descriptor, NULL,
                  val_to_str(desc_type, scsi_sense_desc_type_val, "Unknown (0x%02x)"));
       proto_tree_add_item(desc_tree, hf_scsi_sns_desc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
       proto_tree_add_item(desc_tree, hf_scsi_sns_desc_length, tvb, offset+1, 1, ENC_BIG_ENDIAN);
       switch (desc_type) {
          case 2:
             /*sense key specific*/
             if (desc_length==6) {
                    dissect_scsi_sns_specific_info(tvb,desc_tree,offset+4,sense_key);
             }
             break;
          case 6:
             /*OSD object identification*/
             if (desc_length==0x1e) {
                 static const int *command_functions[] = {
                     &hf_scsi_sns_osd_object_validation,
                     &hf_scsi_sns_osd_object_cmd_cap_v,
                     &hf_scsi_sns_osd_object_command,
                     &hf_scsi_sns_osd_object_imp_st_att,
                     &hf_scsi_sns_osd_object_sa_cap_v,
                     &hf_scsi_sns_osd_object_set_att,
                     &hf_scsi_sns_osd_object_ga_cap_v,
                     &hf_scsi_sns_osd_object_get_att,
                     NULL
                 };
                 proto_tree_add_bitmask(desc_tree, tvb, offset+8, hf_scsi_sns_osd_object_not_initiated, ett_sense_osd_not_initiated, command_functions, ENC_BIG_ENDIAN);
                 proto_tree_add_bitmask(desc_tree, tvb, offset+12, hf_scsi_sns_osd_object_completed, ett_sense_osd_completed, command_functions, ENC_BIG_ENDIAN);
                 proto_tree_add_item(desc_tree, hf_scsi_sns_osd_partition_id, tvb, offset+16, 8, ENC_BIG_ENDIAN);
                 proto_tree_add_item(desc_tree, hf_scsi_sns_osd_object_id, tvb, offset+24, 8, ENC_BIG_ENDIAN);
             }
             break;
          case 8:
            /*OSD attribute identification*/
            offset+=4;
            while (offset+8<=desc_end) {
                const attribute_page_numbers_t *apn;
                guint32 page,number;
                page=tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(desc_tree, hf_scsi_sns_osd_attr_page,   tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                number=tvb_get_ntohl(tvb, offset);
                item=proto_tree_add_item(desc_tree, hf_scsi_sns_osd_attr_number, tvb, offset, 4, ENC_BIG_ENDIAN);
                apn=osd_lookup_attribute(page,number);
                offset+=4;
                if (apn) {
                    proto_item_append_text(item, " (%s)", apn->name);
                } else {
                    proto_item_append_text(item, " (Unknown)");
                }
            }
          default:
             break;
       }
       offset += desc_length+2;
    }
}

static void
dissect_scsi_sense(tvbuff_t *tvb, proto_tree *sns_tree, guint offset)
{
    guint8 sense_type;

    proto_tree_add_item(sns_tree, hf_scsi_sns_errtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    sense_type = tvb_get_guint8(tvb, offset) & 0x7f;

    switch (sense_type) {
    case 0x70:
    case 0x71:
        dissect_scsi_fix_snsinfo(tvb, sns_tree, offset);
        break;
    case 0x72:
    case 0x73:
        dissect_scsi_descriptor_snsinfo(tvb, sns_tree, offset);
        break;
    }
}

void
dissect_spc_requestsense(tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item(tree, hf_scsi_alloclen, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    } else if (!isreq) {
        dissect_scsi_sense(tvb, tree, offset);
    }
}

void
dissect_spc_reserve6(tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_spc_reserve10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_scsi_release_flags, tvb, offset, 1,
                                   flags,
                                   "Flags: 3rd Party ID = %u, LongID = %u",
                                   flags & 0x10, flags & 0x2);
        if ((flags & 0x12) == 0x10) {
            proto_tree_add_item(tree, hf_scsi_release_thirdpartyid, tvb,
                                offset+2, 1, ENC_NA);
        }
        proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_spc_testunitready(tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}






void
dissect_spc_senddiagnostic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb _U_,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree && !isreq)
        return;

    proto_tree_add_item(tree, hf_scsi_senddiag_st_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_senddiag_pf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_senddiag_st, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_senddiag_devoff, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_senddiag_unitoff, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_paramlen16, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                           ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
}

void
dissect_spc_writebuffer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb _U_,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree && !isreq)
        return;

    proto_tree_add_item(tree, hf_scsi_wb_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_wb_bufferid, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_wb_bufoffset, tvb, offset+2, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_paramlen24, tvb, offset+5, 3, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
                           ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
}

static void
dissect_scsi_varlencdb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item(tree, hf_scsi_control, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_add_cdblen, tvb, offset+6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_scsi_svcaction, tvb, offset+7, 2, ENC_BIG_ENDIAN);

    }
}

void
dissect_scsi_rsp(tvbuff_t *tvb, packet_info *pinfo,
                 proto_tree *tree, itlq_nexus_t *itlq, itl_nexus_t *itl,
                 guint8 scsi_status)
{
    proto_item       *ti;
    proto_tree       *scsi_tree = NULL;
    cmdset_t         *csdata;
    scsi_task_data_t *cdata;

    cdata = wmem_new(wmem_packet_scope(), scsi_task_data_t);
    cdata->itl = itl;
    cdata->itlq = itlq;
    cdata->type = SCSI_PDU_TYPE_RSP;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    csdata = get_cmdset_data(itlq, itl);   /* will g_assert if itlq is null */

    /* Nothing really to do here, just print some stuff passed to us
     */
    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_scsi, tvb, 0,
                                            0, "SCSI Response (%s)",
                                            val_to_str_ext(itlq->scsi_opcode,
                                                           csdata->cdb_vals_ext,
                                                           "CDB:0x%02x"));
        scsi_tree = proto_item_add_subtree(ti, ett_scsi);
    }

    ti = proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);


    if (itl) {
        ti = proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
        PROTO_ITEM_SET_GENERATED(ti);

        if (itlq->scsi_opcode != 0xffff) {
            ti = proto_tree_add_uint(scsi_tree, csdata->hf_opcode, tvb, 0, 0, itlq->scsi_opcode);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    if (itlq->first_exchange_frame) {
        nstime_t delta_time;
        ti = proto_tree_add_uint(scsi_tree, hf_scsi_request_frame, tvb, 0, 0, itlq->first_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
        nstime_delta(&delta_time, &pinfo->abs_ts, &itlq->fc_time);
        ti = proto_tree_add_time(scsi_tree, hf_scsi_time, tvb, 0, 0, &delta_time);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(scsi_tree, hf_scsi_status, tvb, 0, 0, scsi_status);
    PROTO_ITEM_SET_GENERATED(ti);
    col_add_fstr(pinfo->cinfo, COL_INFO, "SCSI: Response LUN: 0x%02x (%s) (%s)", itlq->lun,
                     val_to_str_ext(itlq->scsi_opcode, csdata->cdb_vals_ext, "CDB:0x%02x"),
                     val_to_str(scsi_status, scsi_status_val, "Unknown (0x%08x)"));

    col_set_fence(pinfo->cinfo, COL_INFO);
}

void
dissect_scsi_snsinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint offset, guint snslen, itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    proto_item       *ti;
    proto_tree       *sns_tree = NULL;
    const char       *old_proto;
    scsi_task_data_t *cdata;

    cdata = wmem_new(wmem_packet_scope(), scsi_task_data_t);
    cdata->itl = itl;
    cdata->itlq = itlq;
    cdata->type = SCSI_PDU_TYPE_SNS;
    tap_queue_packet(scsi_tap, pinfo, cdata);


    old_proto = pinfo->current_proto;
    pinfo->current_proto="SCSI";

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_scsi, tvb, offset,
                                            snslen, "SCSI: SNS Info");
        sns_tree = proto_item_add_subtree(ti, ett_scsi);
    }


    ti = proto_tree_add_uint(sns_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);
    col_append_fstr(pinfo->cinfo, COL_INFO, " LUN:0x%02x ", itlq->lun);

    col_set_fence(pinfo->cinfo, COL_INFO);

    dissect_scsi_sense(tvb, sns_tree, offset);

    pinfo->current_proto = old_proto;
}


static scsi_cdb_table_t spc[256] = {
    /*SPC 0x00*/{dissect_spc_testunitready},
    /*SPC 0x01*/{NULL},
    /*SPC 0x02*/{NULL},
    /*SPC 0x03*/{dissect_spc_requestsense},
    /*SPC 0x04*/{NULL},
    /*SPC 0x05*/{NULL},
    /*SPC 0x06*/{NULL},
    /*SPC 0x07*/{NULL},
    /*SPC 0x08*/{NULL},
    /*SPC 0x09*/{NULL},
    /*SPC 0x0a*/{NULL},
    /*SPC 0x0b*/{NULL},
    /*SPC 0x0c*/{NULL},
    /*SPC 0x0d*/{NULL},
    /*SPC 0x0e*/{NULL},
    /*SPC 0x0f*/{NULL},
    /*SPC 0x10*/{NULL},
    /*SPC 0x11*/{NULL},
    /*SPC 0x12*/{dissect_spc_inquiry},
    /*SPC 0x13*/{NULL},
    /*SPC 0x14*/{NULL},
    /*SPC 0x15*/{dissect_spc_modeselect6},
    /*SPC 0x16*/{dissect_spc_reserve6},
    /*SPC 0x17*/{dissect_spc_release6},
    /*SPC 0x18*/{NULL},
    /*SPC 0x19*/{NULL},
    /*SPC 0x1a*/{dissect_spc_modesense6},
    /*SPC 0x1b*/{NULL},
    /*SPC 0x1c*/{NULL},
    /*SPC 0x1d*/{dissect_spc_senddiagnostic},
    /*SPC 0x1e*/{dissect_spc_preventallowmediaremoval},
    /*SPC 0x1f*/{NULL},
    /*SPC 0x20*/{NULL},
    /*SPC 0x21*/{NULL},
    /*SPC 0x22*/{NULL},
    /*SPC 0x23*/{NULL},
    /*SPC 0x24*/{NULL},
    /*SPC 0x25*/{NULL},
    /*SPC 0x26*/{NULL},
    /*SPC 0x27*/{NULL},
    /*SPC 0x28*/{NULL},
    /*SPC 0x29*/{NULL},
    /*SPC 0x2a*/{NULL},
    /*SPC 0x2b*/{NULL},
    /*SPC 0x2c*/{NULL},
    /*SPC 0x2d*/{NULL},
    /*SPC 0x2e*/{NULL},
    /*SPC 0x2f*/{NULL},
    /*SPC 0x30*/{NULL},
    /*SPC 0x31*/{NULL},
    /*SPC 0x32*/{NULL},
    /*SPC 0x33*/{NULL},
    /*SPC 0x34*/{NULL},
    /*SPC 0x35*/{NULL},
    /*SPC 0x36*/{NULL},
    /*SPC 0x37*/{NULL},
    /*SPC 0x38*/{NULL},
    /*SPC 0x39*/{NULL},
    /*SPC 0x3a*/{NULL},
    /*SPC 0x3b*/{dissect_spc_writebuffer},
    /*SPC 0x3c*/{NULL},
    /*SPC 0x3d*/{NULL},
    /*SPC 0x3e*/{NULL},
    /*SPC 0x3f*/{NULL},
    /*SPC 0x40*/{NULL},
    /*SPC 0x41*/{NULL},
    /*SPC 0x42*/{NULL},
    /*SPC 0x43*/{NULL},
    /*SPC 0x44*/{NULL},
    /*SPC 0x45*/{NULL},
    /*SPC 0x46*/{NULL},
    /*SPC 0x47*/{NULL},
    /*SPC 0x48*/{NULL},
    /*SPC 0x49*/{NULL},
    /*SPC 0x4a*/{NULL},
    /*SPC 0x4b*/{NULL},
    /*SPC 0x4c*/{dissect_spc_logselect},
    /*SPC 0x4d*/{dissect_spc_logsense},
    /*SPC 0x4e*/{NULL},
    /*SPC 0x4f*/{NULL},
    /*SPC 0x50*/{NULL},
    /*SPC 0x51*/{NULL},
    /*SPC 0x52*/{NULL},
    /*SPC 0x53*/{NULL},
    /*SPC 0x54*/{NULL},
    /*SPC 0x55*/{dissect_spc_modeselect10},
    /*SPC 0x56*/{dissect_spc_reserve10},
    /*SPC 0x57*/{dissect_spc_release10},
    /*SPC 0x58*/{NULL},
    /*SPC 0x59*/{NULL},
    /*SPC 0x5a*/{dissect_spc_modesense10},
    /*SPC 0x5b*/{NULL},
    /*SPC 0x5c*/{NULL},
    /*SPC 0x5d*/{NULL},
    /*SPC 0x5e*/{dissect_spc_persistentreservein},
    /*SPC 0x5f*/{dissect_spc_persistentreserveout},
    /*SPC 0x60*/{NULL},
    /*SPC 0x61*/{NULL},
    /*SPC 0x62*/{NULL},
    /*SPC 0x63*/{NULL},
    /*SPC 0x64*/{NULL},
    /*SPC 0x65*/{NULL},
    /*SPC 0x66*/{NULL},
    /*SPC 0x67*/{NULL},
    /*SPC 0x68*/{NULL},
    /*SPC 0x69*/{NULL},
    /*SPC 0x6a*/{NULL},
    /*SPC 0x6b*/{NULL},
    /*SPC 0x6c*/{NULL},
    /*SPC 0x6d*/{NULL},
    /*SPC 0x6e*/{NULL},
    /*SPC 0x6f*/{NULL},
    /*SPC 0x70*/{NULL},
    /*SPC 0x71*/{NULL},
    /*SPC 0x72*/{NULL},
    /*SPC 0x73*/{NULL},
    /*SPC 0x74*/{NULL},
    /*SPC 0x75*/{NULL},
    /*SPC 0x76*/{NULL},
    /*SPC 0x77*/{NULL},
    /*SPC 0x78*/{NULL},
    /*SPC 0x79*/{NULL},
    /*SPC 0x7a*/{NULL},
    /*SPC 0x7b*/{NULL},
    /*SPC 0x7c*/{NULL},
    /*SPC 0x7d*/{NULL},
    /*SPC 0x7e*/{NULL},
    /*SPC 0x7f*/{dissect_scsi_varlencdb},
    /*SPC 0x80*/{NULL},
    /*SPC 0x81*/{NULL},
    /*SPC 0x82*/{NULL},
    /*SPC 0x83*/{dissect_spc_extcopy},
    /*SPC 0x84*/{dissect_spc_recvcopy},
    /*SPC 0x85*/{NULL},
    /*SPC 0x86*/{NULL},
    /*SPC 0x87*/{NULL},
    /*SPC 0x88*/{NULL},
    /*SPC 0x89*/{NULL},
    /*SPC 0x8a*/{NULL},
    /*SPC 0x8b*/{NULL},
    /*SPC 0x8c*/{NULL},
    /*SPC 0x8d*/{NULL},
    /*SPC 0x8e*/{NULL},
    /*SPC 0x8f*/{NULL},
    /*SPC 0x90*/{NULL},
    /*SPC 0x91*/{NULL},
    /*SPC 0x92*/{NULL},
    /*SPC 0x93*/{NULL},
    /*SPC 0x94*/{NULL},
    /*SPC 0x95*/{NULL},
    /*SPC 0x96*/{NULL},
    /*SPC 0x97*/{NULL},
    /*SPC 0x98*/{NULL},
    /*SPC 0x99*/{NULL},
    /*SPC 0x9a*/{NULL},
    /*SPC 0x9b*/{NULL},
    /*SPC 0x9c*/{NULL},
    /*SPC 0x9d*/{NULL},
    /*SPC 0x9e*/{NULL},
    /*SPC 0x9f*/{NULL},
    /*SPC 0xa0*/{dissect_spc_reportluns},
    /*SPC 0xa1*/{NULL},
    /*SPC 0xa2*/{NULL},
    /*SPC 0xa3*/{dissect_spc_reportdeviceidentifier},
    /*SPC 0xa4*/{NULL},
    /*SPC 0xa5*/{NULL},
    /*SPC 0xa6*/{NULL},
    /*SPC 0xa7*/{NULL},
    /*SPC 0xa8*/{NULL},
    /*SPC 0xa9*/{NULL},
    /*SPC 0xaa*/{NULL},
    /*SPC 0xab*/{NULL},
    /*SPC 0xac*/{NULL},
    /*SPC 0xad*/{NULL},
    /*SPC 0xae*/{NULL},
    /*SPC 0xaf*/{NULL},
    /*SPC 0xb0*/{NULL},
    /*SPC 0xb1*/{NULL},
    /*SPC 0xb2*/{NULL},
    /*SPC 0xb3*/{NULL},
    /*SPC 0xb4*/{NULL},
    /*SPC 0xb5*/{NULL},
    /*SPC 0xb6*/{NULL},
    /*SPC 0xb7*/{NULL},
    /*SPC 0xb8*/{NULL},
    /*SPC 0xb9*/{NULL},
    /*SPC 0xba*/{NULL},
    /*SPC 0xbb*/{NULL},
    /*SPC 0xbc*/{NULL},
    /*SPC 0xbd*/{NULL},
    /*SPC 0xbe*/{NULL},
    /*SPC 0xbf*/{NULL},
    /*SPC 0xc0*/{NULL},
    /*SPC 0xc1*/{NULL},
    /*SPC 0xc2*/{NULL},
    /*SPC 0xc3*/{NULL},
    /*SPC 0xc4*/{NULL},
    /*SPC 0xc5*/{NULL},
    /*SPC 0xc6*/{NULL},
    /*SPC 0xc7*/{NULL},
    /*SPC 0xc8*/{NULL},
    /*SPC 0xc9*/{NULL},
    /*SPC 0xca*/{NULL},
    /*SPC 0xcb*/{NULL},
    /*SPC 0xcc*/{NULL},
    /*SPC 0xcd*/{NULL},
    /*SPC 0xce*/{NULL},
    /*SPC 0xcf*/{NULL},
    /*SPC 0xd0*/{NULL},
    /*SPC 0xd1*/{NULL},
    /*SPC 0xd2*/{NULL},
    /*SPC 0xd3*/{NULL},
    /*SPC 0xd4*/{NULL},
    /*SPC 0xd5*/{NULL},
    /*SPC 0xd6*/{NULL},
    /*SPC 0xd7*/{NULL},
    /*SPC 0xd8*/{NULL},
    /*SPC 0xd9*/{NULL},
    /*SPC 0xda*/{NULL},
    /*SPC 0xdb*/{NULL},
    /*SPC 0xdc*/{NULL},
    /*SPC 0xdd*/{NULL},
    /*SPC 0xde*/{NULL},
    /*SPC 0xdf*/{NULL},
    /*SPC 0xe0*/{NULL},
    /*SPC 0xe1*/{NULL},
    /*SPC 0xe2*/{NULL},
    /*SPC 0xe3*/{NULL},
    /*SPC 0xe4*/{NULL},
    /*SPC 0xe5*/{NULL},
    /*SPC 0xe6*/{NULL},
    /*SPC 0xe7*/{NULL},
    /*SPC 0xe8*/{NULL},
    /*SPC 0xe9*/{NULL},
    /*SPC 0xea*/{NULL},
    /*SPC 0xeb*/{NULL},
    /*SPC 0xec*/{NULL},
    /*SPC 0xed*/{NULL},
    /*SPC 0xee*/{NULL},
    /*SPC 0xef*/{NULL},
    /*SPC 0xf0*/{NULL},
    /*SPC 0xf1*/{NULL},
    /*SPC 0xf2*/{NULL},
    /*SPC 0xf3*/{NULL},
    /*SPC 0xf4*/{NULL},
    /*SPC 0xf5*/{NULL},
    /*SPC 0xf6*/{NULL},
    /*SPC 0xf7*/{NULL},
    /*SPC 0xf8*/{NULL},
    /*SPC 0xf9*/{NULL},
    /*SPC 0xfa*/{NULL},
    /*SPC 0xfb*/{NULL},
    /*SPC 0xfc*/{NULL},
    /*SPC 0xfd*/{NULL},
    /*SPC 0xfe*/{NULL},
    /*SPC 0xff*/{NULL}
};


/* This function must be called with valid pointers for both itlq and itl */
void
dissect_scsi_cdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 gint devtype_arg _U_, itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    int               offset    = 0;
    proto_item       *ti;
    proto_tree       *scsi_tree = NULL;
    guint8            opcode;
#if 0
    scsi_device_type  devtype;
#endif
    const gchar      *valstr;
    scsi_task_data_t *cdata;
    const char       *old_proto;
    cmdset_t         *csdata;


    old_proto = pinfo->current_proto;
    pinfo->current_proto="SCSI";

    if (!itlq) {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    if (!itl) {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    opcode = tvb_get_guint8(tvb, offset);
    itlq->scsi_opcode = opcode;
    csdata = get_cmdset_data(itlq, itl);

#if 0 /* XXX: devtype never actually used ?? */
    if (devtype_arg != SCSI_DEV_UNKNOWN) {
        devtype = devtype_arg;
    } else {
        if (itl) {
            devtype = itl->cmdset;
        } else {
            devtype = (scsi_device_type)scsi_def_devtype;
        }
    }
#endif

    if ((valstr = try_val_to_str_ext(opcode, &scsi_spc_vals_ext)) == NULL) {
        valstr = try_val_to_str_ext(opcode, csdata->cdb_vals_ext);
    }

    if (valstr != NULL) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "SCSI: %s LUN: 0x%02x ", valstr, itlq->lun);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "SCSI Command: 0x%02x LUN:0x%02x ", opcode, itlq->lun);
    }
    /* make sure no one will overwrite this in the info column */
    col_set_fence(pinfo->cinfo, COL_INFO);

    cdata = wmem_new(wmem_packet_scope(), scsi_task_data_t);
    cdata->itl = itl;
    cdata->itlq = itlq;
    cdata->type = SCSI_PDU_TYPE_CDB;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_scsi, tvb, 0,
                                            -1, "SCSI CDB %s",
                                            val_to_str_ext(opcode,
                                                           csdata->cdb_vals_ext,
                                                           "0x%02x")
            );
        scsi_tree = proto_item_add_subtree(ti, ett_scsi);
    }

    ti = proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);

    if (itl) {
        ti = proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if (itlq->last_exchange_frame) {
        ti = proto_tree_add_uint(scsi_tree, hf_scsi_response_frame, tvb, 0, 0, itlq->last_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    if (valstr != NULL) {
        proto_tree_add_uint_format(scsi_tree, csdata->hf_opcode, tvb,
                                   offset, 1,
                                   tvb_get_guint8(tvb, offset),
                                   "Opcode: %s (0x%02x)", valstr,
                                   opcode);
    } else {
        proto_tree_add_item(scsi_tree, hf_scsi_spcopcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    if (csdata->cdb_table[opcode].func) {
        csdata->cdb_table[opcode].func(tvb, pinfo, scsi_tree, offset+1,
                                       TRUE, TRUE, 0, cdata);
    } else if (spc[opcode].func) {
        spc[opcode].func(tvb, pinfo, scsi_tree, offset+1,
                         TRUE, TRUE, 0, cdata);
    } else {
        call_data_dissector(tvb, pinfo, scsi_tree);
    }

    pinfo->current_proto = old_proto;
}

void
dissect_scsi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     gboolean isreq, itlq_nexus_t *itlq, itl_nexus_t *itl,
                     guint32 relative_offset)
{
    int               offset          = 0;
    proto_item       *ti;
    proto_tree       *scsi_tree       = NULL;
    guint8            opcode;
    scsi_task_data_t *cdata;
    int               payload_len;
    const char       *old_proto;
    cmdset_t         *csdata;
    guint32           expected_length;
    fragment_head    *ipfd_head;
    tvbuff_t         *next_tvb        = tvb;
    gboolean          update_col_info = TRUE;
    gboolean          more_frags      = FALSE;

    if (!itlq || !itl) {
        /* we have no record of this exchange and so we can't dissect the
         * payload
         */
        expert_add_info(pinfo, tree, &ei_scsi_unknown_scsi_exchange);
        return;
    }

    payload_len = tvb_reported_length(tvb);
    cdata = wmem_new(wmem_packet_scope(), scsi_task_data_t);
    cdata->itl = itl;
    cdata->itlq = itlq;
    cdata->type = SCSI_PDU_TYPE_CDB;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    csdata = get_cmdset_data(itlq, itl);

    old_proto = pinfo->current_proto;
    pinfo->current_proto="SCSI";

    opcode = (guint8) cdata->itlq->scsi_opcode;

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_scsi, tvb, offset,
                                            payload_len,
                                            "SCSI Payload (%s %s)",
                                            val_to_str_ext(opcode,
                                                           csdata->cdb_vals_ext,
                                                           "CDB:0x%02x"),
                                            isreq ? "Request Data" : "Response Data");
        scsi_tree = proto_item_add_subtree(ti, ett_scsi);
    }

    col_add_fstr(pinfo->cinfo, COL_INFO,
                    "SCSI: Data %s LUN: 0x%02x (%s %s) ",
                    isreq ? "Out" : "In",
                    itlq->lun,
                    val_to_str_ext(opcode, csdata->cdb_vals_ext, "0x%02x"),
                    isreq ? "Request Data" : "Response Data");

    col_set_fence(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);

    if (itl) {
        ti = proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK,
                                        "Command Set:%s (0x%02x) %s",
                                        val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"),
                                        itl->cmdset&SCSI_CMDSET_MASK,
                                        itl->cmdset&SCSI_CMDSET_DEFAULT ? "(Using default commandset)" : "");
        PROTO_ITEM_SET_GENERATED(ti);

        if (itlq && (itlq->scsi_opcode != 0xffff)) {
            ti = proto_tree_add_uint(scsi_tree, csdata->hf_opcode, tvb, 0, 0, itlq->scsi_opcode);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    if (itlq->first_exchange_frame) {
        ti = proto_tree_add_uint(scsi_tree, hf_scsi_request_frame, tvb, 0, 0, itlq->first_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if (itlq->last_exchange_frame) {
        ti = proto_tree_add_uint(scsi_tree, hf_scsi_response_frame, tvb, 0, 0, itlq->last_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* If we don't know the CDB opcode there is no point in trying to
     * dissect the data.
     */
    if ( !itlq->first_exchange_frame ) {
        call_data_dissector(tvb, pinfo, scsi_tree);
        goto end_of_payload;
    }

    /* If we are not doing data reassembly we only call the dissector
     * for the very first data in/out pdu in each transfer
     */
    if (!scsi_defragment) {
        if (relative_offset) {
            call_data_dissector(tvb, pinfo, scsi_tree);
            goto end_of_payload;
        } else {
            goto dissect_the_payload;
        }
    }

    /* If we don't have the entire PDU there is no point in even trying
     * reassembly
     */
    if (tvb_captured_length_remaining(tvb, offset) != tvb_reported_length_remaining(tvb, offset)) {
        if (relative_offset) {
            call_data_dissector(tvb, pinfo, scsi_tree);
            goto end_of_payload;
        } else {
            goto dissect_the_payload;
        }
    }


    /* What is the expected data length for this transfer */
    if ( (itlq->task_flags&(SCSI_DATA_READ|SCSI_DATA_WRITE)) == (SCSI_DATA_READ|SCSI_DATA_WRITE) ) {
        /* This is a bidirectional transfer */
        if (isreq) {
            expected_length = itlq->data_length;
        } else {
            expected_length = itlq->bidir_data_length;
        }
    } else {
        /* This is a unidirectional transfer */
        expected_length = itlq->data_length;
    }

    /* If this PDU already contains all the expected data we don't have to do
     * reassembly.
     */
    if ( (!relative_offset) && ((guint32)tvb_reported_length_remaining(tvb, offset) == expected_length) ) {
        goto dissect_the_payload;
    }


    /* Start reassembly */

    if (tvb_reported_length_remaining(tvb, offset) < 0) {
        goto end_of_payload;
    }
    if ((tvb_reported_length_remaining(tvb,offset) + relative_offset) != expected_length) {
        more_frags = TRUE;
    }
    ipfd_head = fragment_add_check(&scsi_reassembly_table, tvb, offset,
                                   pinfo,
                                   itlq->first_exchange_frame, /* key */
                                   NULL,
                                   relative_offset,
                                   tvb_reported_length_remaining(tvb, offset),
                                   more_frags);
    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled SCSI DATA", ipfd_head, &scsi_frag_items, &update_col_info, tree);

    if ( ipfd_head && (ipfd_head->reassembled_in != pinfo->num) ) {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "[Reassembled in #%u] ",
                             ipfd_head->reassembled_in);
    }


dissect_the_payload:
    if (!next_tvb) {
        /* reassembly has not yet finished so we don't have a tvb yet */
        goto end_of_payload;
    }
    if (tree == NULL) {
        /*
         * We have to dissect INQUIRY responses, in order to determine the
         * types of devices.
         *
         * We don't bother dissecting other payload if we're not building
         * a protocol tree.
         *
         * We assume opcode 0x12 is always INQUIRY regardless of the
         * commandset used.
         */
        if (opcode == SCSI_SPC_INQUIRY) {
            dissect_spc_inquiry(next_tvb, pinfo, scsi_tree, offset, isreq,
                                FALSE, payload_len, cdata);
        }
    } else {
        /*
          All commandsets support SPC?
        */
        if (csdata->cdb_table && (csdata->cdb_table)[opcode].func) {
            (csdata->cdb_table)[opcode].func(next_tvb, pinfo, scsi_tree, offset,
                                             isreq, FALSE, payload_len, cdata);
        } else if (spc[opcode].func) {
            spc[opcode].func(next_tvb, pinfo, scsi_tree, offset,
                             isreq, FALSE, payload_len, cdata);
        } else { /* don't know this CDB */
            call_data_dissector(next_tvb, pinfo, scsi_tree);
        }
    }

end_of_payload:
    pinfo->current_proto = old_proto;
}

static cmdset_t *
get_cmdset_data(itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    cmdset_t *csdata;
    guint8    cmdset;

    /* we must have an itlq structure */
    if (!itlq) {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    if (itl) {
        if (itl->cmdset == 0xff) {
            itl->cmdset = scsi_def_devtype|SCSI_CMDSET_DEFAULT;
        }
        cmdset = itl->cmdset;
    } else {
        cmdset = scsi_def_devtype;
    }

    csdata = wmem_new(wmem_packet_scope(), cmdset_t);

    switch(cmdset&SCSI_CMDSET_MASK) {
    case SCSI_DEV_SBC:
        csdata->hf_opcode    = hf_scsi_sbc_opcode;
        csdata->cdb_vals_ext = &scsi_sbc_vals_ext;
        csdata->cdb_table    = scsi_sbc_table;
        break;
    case SCSI_DEV_CDROM:
        csdata->hf_opcode    = hf_scsi_mmc_opcode;
        csdata->cdb_vals_ext = &scsi_mmc_vals_ext;
        csdata->cdb_table    = scsi_mmc_table;
        break;
    case SCSI_DEV_SSC:
        csdata->hf_opcode    = hf_scsi_ssc_opcode;
        csdata->cdb_vals_ext = &scsi_ssc_vals_ext;
        csdata->cdb_table    = scsi_ssc_table;
        break;
    case SCSI_DEV_SMC:
        csdata->hf_opcode    = hf_scsi_smc_opcode;
        csdata->cdb_vals_ext = &scsi_smc_vals_ext;
        csdata->cdb_table    = scsi_smc_table;
        break;
    case SCSI_DEV_OSD:
        csdata->hf_opcode    = hf_scsi_osd_opcode;
        csdata->cdb_vals_ext = &scsi_osd_vals_ext;
        csdata->cdb_table    = scsi_osd_table;
        break;
    default:
        csdata->hf_opcode    = hf_scsi_spcopcode;
        csdata->cdb_vals_ext = &scsi_spc_vals_ext;
        csdata->cdb_table    = spc;
        break;
    }

    return csdata;
}


void
proto_register_scsi(void)
{
    static hf_register_info hf[] = {
        { &hf_scsi_status,
          { "Status", "scsi.status", FT_UINT8, BASE_HEX,
            VALS(scsi_status_val), 0, "SCSI command status value", HFILL }},
        { &hf_scsi_spcopcode,
          {"SPC-2 Opcode", "scsi.spc.opcode", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
           &scsi_spc_vals_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_control,
          {"Control", "scsi.cdb.control", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_control_vendor_specific,
          {"Vendor specific", "scsi.cdb.control.vendorspecific", FT_UINT8,
           BASE_HEX, NULL, 0xC0, NULL, HFILL}},
        { &hf_scsi_control_reserved,
          {"Reserved", "scsi.cdb.control.reserved", FT_UINT8, BASE_HEX, NULL,
           0x38, NULL, HFILL}},
        { &hf_scsi_control_naca,
          {"NACA", "scsi.cdb.control.naca", FT_BOOLEAN, 8,
           TFS(&scsi_naca_tfs), 0x04, NULL, HFILL}},
        { &hf_scsi_control_obs1,
          {"Obsolete", "scsi.cdb.control.obs1", FT_UINT8, BASE_HEX,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_control_obs2,
          {"Obsolete", "scsi.cdb.control.obs2", FT_UINT8, BASE_HEX,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_inq_control,
          {"Control", "scsi.cdb.inq.control", FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_inquiry_flags,
          {"Inquiry Flags", "scsi.inquiry.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_inquiry_evpd_page,
          {"EVPD Page Code", "scsi.inquiry.evpd.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_evpd_pagecode_val), 0x0, NULL, HFILL}},
        { &hf_scsi_inquiry_cmdt_page,
          {"CMDT Page Code", "scsi.inquiry.cmdt.pagecode", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_alloclen,
          {"Allocation Length", "scsi.cdb.alloclen", FT_UINT8, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_paramlen,
          {"Parameter Length", "scsi.cdb.paramlen", FT_UINT8, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_log_pc,
          {"Page Control", "scsi.log.pc", FT_UINT8, BASE_DEC,
           VALS(scsi_log_pc_val), 0xC0, NULL, HFILL}},
        { &hf_scsi_log_pagecode,
          {"Page Code", "scsi.log.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_log_page_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_paramlen16,
          {"Parameter Length", "scsi.cdb.paramlen16", FT_UINT16, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_modesel_flags,
          {"Mode Sense/Select Flags", "scsi.cdb.mode.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_alloclen16,
          {"Allocation Length", "scsi.cdb.alloclen16", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_modesns_pc,
          {"Page Control", "scsi.mode.pc", FT_UINT8, BASE_DEC,
           VALS(scsi_modesns_pc_val), 0xC0, NULL, HFILL}},
        { &hf_scsi_spc_subpagecode,
          {"SubPage Code", "scsi.mode.spc.subpagecode", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_spc_pagecode,
          {"SPC-2 Page Code", "scsi.mode.spc.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_spc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_sbcpagecode,
          {"SBC-2 Page Code", "scsi.mode.sbc.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_sbc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_sscpagecode,
          {"SSC-2 Page Code", "scsi.mode.ssc.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_ssc2_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_mmcpagecode,
          {"MMC-5 Page Code", "scsi.mode.mmc.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_mmc5_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_smcpagecode,
          {"SMC-2 Page Code", "scsi.mode.smc.pagecode", FT_UINT8, BASE_HEX,
           VALS(scsi_smc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_modesns_flags,
          {"Mode Sense Flags", "scsi.mode.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_persresvin_svcaction,
          {"Service Action", "scsi.persresvin.svcaction", FT_UINT8, BASE_HEX,
           VALS(scsi_persresvin_svcaction_val), 0x1F, NULL, HFILL}},
        { &hf_scsi_persresvout_svcaction,
          {"Service Action", "scsi.persresvout.svcaction", FT_UINT8, BASE_HEX,
           VALS(scsi_persresvout_svcaction_val), 0x1F, NULL, HFILL}},
        { &hf_scsi_persresv_scope,
          {"Reservation Scope", "scsi.persresv.scope", FT_UINT8, BASE_HEX,
           VALS(scsi_persresv_scope_val), 0xF0, NULL, HFILL}},
        { &hf_scsi_persresv_type,
          {"Reservation Type", "scsi.persresv.type", FT_UINT8, BASE_HEX,
           VALS(scsi_persresv_type_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_persresvout_reskey,
          {"Reservation Key", "scsi.persresv.reskey", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_persresvout_sareskey,
          {"Service Action Reservation Key", "scsi.persresv.sareskey", FT_BYTES,
           BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_persresvout_obsolete,
          {"Obsolete", "scsi.presresv.obs", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_persresvout_control,
          {"Control", "scsi.presresv.control", FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},
        /* Service action REGISTER AND MOVE */
        { &hf_scsi_persresv_control_rsvd,
          {"Reserved", "scsi.persresv.control.reserved", FT_UINT8, BASE_HEX,
           NULL, 0xFC, NULL, HFILL}},
        { &hf_scsi_persresv_control_unreg,
          {"unreg", "scsi.persresv.control.unreg", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        /* Other service actions than REGISTER AND MOVE */
        { &hf_scsi_persresv_control_rsvd1,
          {"Reserved", "scsi.persresv.control.reserved1", FT_UINT8, BASE_HEX,
           NULL, 0xF0, NULL, HFILL}},
        { &hf_scsi_persresv_control_rsvd2,
          {"Reserved", "scsi.persresv.control.reserved2", FT_UINT8, BASE_HEX,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_persresv_control_spec_i_pt,
          {"SPEC_I_PT", "scsi.persresv.control.spec_i_pt", FT_BOOLEAN, 8,
           TFS(&scsi_spec_i_pt_tfs), 0x08, NULL, HFILL}},
        { &hf_scsi_persresv_control_all_tg_pt,
          {"ALL_TG_PT", "scsi.persresv.control.all_tg_pt", FT_BOOLEAN, 8,
           TFS(&scsi_all_tg_pt_tfs), 0x04, NULL, HFILL}},
        { &hf_scsi_persresv_control_aptpl,
          {"aptpl", "scsi.persresv.control.aptpl", FT_BOOLEAN, 8,
           TFS(&scsi_aptpl_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_persresvout_rel_tpi,
          {"rel_tpi", "scsi.persresv.rel_tpi", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_persresvout_transportid_len,
          {"transportid_len", "scsi.persresv.transportid_len",
           FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_persresvout_transportid,
          {"transportid_len", "scsi.persresv.transportid",
           FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_release_flags,
          {"Release Flags", "scsi.release.flags", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_release_thirdpartyid,
          {"Third-Party ID", "scsi.release.thirdpartyid", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_alloclen32,
          {"Allocation Length", "scsi.cdb.alloclen32", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_inq_add_len,
          {"Additional Length", "scsi.inquiry.add_len", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_qualifier,
          {"Qualifier", "scsi.inquiry.qualifier", FT_UINT8, BASE_HEX,
           VALS(scsi_qualifier_val), 0xE0, NULL, HFILL}},
        { &hf_scsi_inq_peripheral,
          {"Peripheral", "scsi.inquiry.peripheral", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_vendor_id,
          {"Vendor Id", "scsi.inquiry.vendor_id", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_product_id,
          {"Product Id", "scsi.inquiry.product_id", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_product_rev,
          {"Product Revision Level", "scsi.inquiry.product_rev", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_vendor_specific,
          {"Vendor Specific", "scsi.inquiry.vendor_specific", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_version_desc,
          {"Version Description", "scsi.inquiry.version_desc", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
           &scsi_verdesc_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_inq_devtype,
          {"Device Type", "scsi.inquiry.devtype", FT_UINT8, BASE_HEX,
           VALS(scsi_devtype_val), SCSI_DEV_BITS, NULL, HFILL}},
        { &hf_scsi_inq_rmb,
          {"Removable", "scsi.inquiry.removable", FT_BOOLEAN, 8,
           TFS(&scsi_removable_val), 0x80, NULL, HFILL}},
        { & hf_scsi_inq_version,
          {"Version", "scsi.inquiry.version", FT_UINT8, BASE_HEX,
           VALS(scsi_inquiry_vers_val), 0x0, NULL, HFILL}},
        { &hf_scsi_inq_reladrflags,
          {"Inquiry RelAdr Flags", "scsi.inquiry.reladrflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_reladr,
          {"RelAdr", "scsi.inquiry.reladr", FT_BOOLEAN, 8, TFS(&reladr_tfs), SCSI_INQ_RELADRFLAGS_RELADR,
           NULL, HFILL}},
        { &hf_scsi_inq_linked,
          {"Linked", "scsi.inquiry.linked", FT_BOOLEAN, 8, TFS(&linked_tfs), SCSI_INQ_RELADRFLAGS_LINKED,
           NULL, HFILL}},
        { &hf_scsi_inq_trandis,
          {"TranDis", "scsi.inquiry.trandis", FT_BOOLEAN, 8, NULL, SCSI_INQ_RELADRFLAGS_TRANDIS,
           NULL, HFILL}},
        { &hf_scsi_inq_cmdque,
          {"CmdQue", "scsi.inquiry.cmdque", FT_BOOLEAN, 8, TFS(&cmdque_tfs), SCSI_INQ_RELADRFLAGS_CMDQUE,
           NULL, HFILL}},
        { &hf_scsi_inq_bqueflags,
          {"Inquiry BQue Flags", "scsi.inquiry.bqueflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_bque,
          {"BQue", "scsi.inquiry.bque", FT_BOOLEAN, 8, TFS(&bque_tfs), SCSI_INQ_BQUEFLAGS_BQUE,
           NULL, HFILL}},
        { &hf_scsi_inq_encserv,
          {"EncServ", "scsi.inquiry.encserv", FT_BOOLEAN, 8, TFS(&encserv_tfs), SCSI_INQ_BQUEFLAGS_ENCSERV,
           NULL, HFILL}},
        { &hf_scsi_inq_multip,
          {"MultiP", "scsi.inquiry.multip", FT_BOOLEAN, 8, TFS(&multip_tfs), SCSI_INQ_BQUEFLAGS_MULTIP,
           NULL, HFILL}},
        { &hf_scsi_inq_mchngr,
          {"MChngr", "scsi.inquiry.mchngr", FT_BOOLEAN, 8, TFS(&mchngr_tfs), SCSI_INQ_BQUEFLAGS_MCHNGR,
           NULL, HFILL}},
        { &hf_scsi_inq_ackreqq,
          {"ACKREQQ", "scsi.inquiry.ackreqq", FT_BOOLEAN, 8, NULL, SCSI_INQ_BQUEFLAGS_ACKREQQ,
           NULL, HFILL}},
        { &hf_scsi_inq_sccsflags,
          {"Inquiry SCCS Flags", "scsi.inquiry.sccsflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_sccs,
          {"SCCS", "scsi.inquiry.sccs", FT_BOOLEAN, 8, TFS(&sccs_tfs), SCSI_INQ_SCCSFLAGS_SCCS,
           NULL, HFILL}},
        { &hf_scsi_inq_acc,
          {"ACC", "scsi.inquiry.acc", FT_BOOLEAN, 8, TFS(&acc_tfs), SCSI_INQ_SCCSFLAGS_ACC,
           NULL, HFILL}},
        { &hf_scsi_inq_tpc,
          {"3PC", "scsi.inquiry.tpc", FT_BOOLEAN, 8, TFS(&tpc_tfs), SCSI_INQ_SCCSFLAGS_TPC,
           NULL, HFILL}},
        { &hf_scsi_inq_protect,
          {"Protect", "scsi.inquiry.protect", FT_BOOLEAN, 8, TFS(&protect_tfs), SCSI_INQ_SCCSFLAGS_PROTECT,
           NULL, HFILL}},
        { &hf_scsi_inq_tpgs,
          {"TPGS", "scsi.inquiry.tpgs", FT_UINT8, BASE_DEC, VALS(inq_tpgs_vals), 0x30,
           NULL, HFILL}},
        { &hf_scsi_inq_acaflags,
          {"Inquiry ACA Flags", "scsi.inquiry.acaflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_control_vendor_specific,
          {"Vendor specific", "scsi.inquiry.control.vendorspecific", FT_UINT8,
           BASE_HEX, NULL, 0xC0, NULL, HFILL}},
        { &hf_scsi_inq_control_reserved,
          {"Reserved", "scsi.inquiry.control.reserved", FT_UINT8, BASE_HEX,
           NULL, 0x38, NULL, HFILL}},
        { &hf_scsi_inq_control_naca,
          {"NACA", "scsi.inquiry.control.naca", FT_BOOLEAN, 8,
           TFS(&scsi_naca_tfs), 0x04, NULL, HFILL}},
        { &hf_scsi_inq_control_obs1,
          {"Obsolete", "scsi.inquiry.control.obs1", FT_UINT8, BASE_HEX,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_inq_control_obs2,
          {"Obsolete", "scsi.inquiry.control.obs2", FT_UINT8, BASE_HEX,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_inq_rmbflags,
          {"Inquiry RMB Flags", "scsi.inquiry.rmbflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_normaca,
          {"NormACA", "scsi.inquiry.normaca", FT_BOOLEAN, 8, TFS(&normaca_tfs), SCSI_INQ_ACAFLAGS_NORMACA,
           NULL, HFILL}},
        { &hf_scsi_inq_hisup,
          {"HiSup", "scsi.inquiry.hisup", FT_BOOLEAN, 8, TFS(&hisup_tfs), SCSI_INQ_ACAFLAGS_HISUP,
           NULL, HFILL}},
        { &hf_scsi_inq_aerc,
          {"AERC", "scsi.inquiry.aerc", FT_BOOLEAN, 8, TFS(&aerc_tfs), SCSI_INQ_ACAFLAGS_AERC,
           "AERC is obsolete from SPC-3 and forward", HFILL}},
        { &hf_scsi_inq_trmtsk,
          {"TrmTsk", "scsi.inquiry.trmtsk", FT_BOOLEAN, 8, TFS(&trmtsk_tfs), SCSI_INQ_ACAFLAGS_TRMTSK,
           "TRMTSK is obsolete from SPC-2 and forward", HFILL}},
        { &hf_scsi_inq_rdf,
          {"Response Data Format", "scsi.inquiry.rdf", FT_UINT8, BASE_DEC, VALS(inq_rdf_vals), 0x0f,
           NULL, HFILL}},
        { &hf_scsi_modesns_errrep,
          {"MRIE", "scsi.mode.mrie", FT_UINT8, BASE_HEX,
           VALS(scsi_modesns_mrie_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_modesns_tst,
          {"Task Set Type", "scsi.mode.tst", FT_UINT8, BASE_DEC,
           VALS(scsi_modesns_tst_val), 0xE0, NULL, HFILL}},
        { &hf_scsi_modesns_qmod,
          {"Queue Algorithm Modifier", "scsi.mode.qmod", FT_UINT8, BASE_HEX,
           VALS(scsi_modesns_qmod_val), 0xF0, NULL, HFILL}},
        { &hf_scsi_modesns_qerr,
          {"Queue Error Management", "scsi.mode.qerr", FT_BOOLEAN, 8,
           TFS(&scsi_modesns_qerr_val), 0x2, NULL, HFILL}},
        { &hf_scsi_modesns_tas,
          {"Task Aborted Status", "scsi.mode.tac", FT_BOOLEAN, 8,
           TFS(&scsi_modesns_tas_val), 0x80, NULL, HFILL}},
        { &hf_scsi_modesns_rac,
          {"Report a Check", "scsi.mode.rac", FT_BOOLEAN, 8,
           TFS(&scsi_modesns_rac_val), 0x40, NULL, HFILL}},
        { &hf_scsi_protocol,
          {"Protocol", "scsi.proto", FT_UINT8, BASE_DEC, VALS(scsi_proto_val),
           0x0F, NULL, HFILL}},
        { &hf_scsi_sns_errtype,
          {"SNS Error Type", "scsi.sns.errtype", FT_UINT8, BASE_HEX,
           VALS(scsi_sns_errtype_val), 0x7F, NULL, HFILL}},
        { &hf_scsi_snskey,
          {"Sense Key", "scsi.sns.key", FT_UINT8, BASE_HEX,
           VALS(scsi_sensekey_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_snsinfo,
          {"Sense Info", "scsi.sns.info", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_addlsnslen,
          {"Additional Sense Length", "scsi.sns.addlen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_asc,
          {"Additional Sense Code", "scsi.sns.asc", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_ascq,
          {"Additional Sense Code Qualifier", "scsi.sns.ascq", FT_UINT8,
           BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ascascq,
          {"Additional Sense Code+Qualifier", "scsi.sns.ascascq", FT_UINT16,
           BASE_HEX|BASE_EXT_STRING, &scsi_asc_val_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_fru,
          {"Field Replaceable Unit Code", "scsi.sns.fru", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sksv,
          {"SKSV", "scsi.sns.sksv", FT_BOOLEAN, 8, NULL, 0x80, NULL,
           HFILL}},
        { &hf_scsi_sks_info,
          {"Sense Key Specific", "scsi.sns.sks_info", FT_UINT24, BASE_HEX, NULL, 0x7FFFFF, NULL, HFILL}},
        { &hf_scsi_sks_fp_cd,
          {"Command/Data", "scsi.sns.sks.fp.cd", FT_UINT24, BASE_HEX, VALS(scsi_sense_sks_fp_cd_val), 0x400000, NULL, HFILL}},
        { &hf_scsi_sks_fp_bpv,
          {"Bit pointer valid", "scsi.sns.sks.fp.bpv", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL}},
        { &hf_scsi_sks_fp_bit,
          {"Bit pointer", "scsi.sns.sks.fp.bit", FT_UINT24, BASE_DEC, NULL, 0x070000, NULL, HFILL}},
        { &hf_scsi_sks_fp_field,
          {"Field pointer", "scsi.sns.sks.fp.field", FT_UINT24, BASE_DEC, NULL, 0x00FFFF, NULL, HFILL}},
        { &hf_scsi_sns_desc_type,
          {"Sense data descriptor type", "scsi.sns.desc.type", FT_UINT8, BASE_HEX, VALS(scsi_sense_desc_type_val), 0, NULL, HFILL}},
        { &hf_scsi_sns_desc_length,
            {"Sense data descriptor length", "scsi.sns.desc.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_not_initiated,
            {"Not initiated", "scsi.sns.desc.osd_object.not_initiated", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_completed,
            {"Completed", "scsi.sns.desc.osd_object.completed", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_validation,
            {"VALIDATION", "scsi.sns.desc.osd_object.validation", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_cmd_cap_v,
            {"CMD_CAP_V", "scsi.sns.desc.osd_object.cmd_cap_v",   FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_command,
            {"COMMAND", "scsi.sns.desc.osd_object.command",       FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_imp_st_att,
            {"IMP_ST_ATT", "scsi.sns.desc.osd_object.imp_st_att", FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_sa_cap_v,
            {"SA_CAP_V", "scsi.sns.desc.osd_object.sa_cap_v",     FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_set_att,
            {"SET_ATT", "scsi.sns.desc.osd_object.set_att",       FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_ga_cap_v,
            {"GA_CAP_V", "scsi.sns.desc.osd_object.ga_cap_v",     FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_get_att,
            {"GET_ATT", "scsi.sns.desc.osd_object.get_att",       FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL}},
        { &hf_scsi_sns_osd_partition_id,
            {"Partition ID", "scsi.sns.desc.osd_object.partition_id", FT_UINT64, BASE_HEX,  NULL, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_object_id,
            {"Object ID", "scsi.sns.desc.osd_object.object_id",  FT_UINT64, BASE_HEX,  NULL, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_attr_page,
            {"Attribute page", "scsi.sns.desc.osd_attr.page",      FT_UINT32, BASE_HEX | BASE_EXT_STRING,  &attributes_page_vals_ext, 0, NULL, HFILL}},
        { &hf_scsi_sns_osd_attr_number,
            {"Attribute number", "scsi.sns.desc.osd_attr.number",  FT_UINT32, BASE_HEX,  NULL, 0, NULL, HFILL}},
        { &hf_scsi_persresv_key,
            {"Reservation Key", "scsi.spc.resv.key", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_persresv_scopeaddr,
          {"Scope Address", "scsi.spc.resv.scopeaddr", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_add_cdblen,
          {"Additional CDB Length", "scsi.spc.addcdblen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_svcaction,
          {"Service Action", "scsi.spc.svcaction", FT_UINT16, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_wb_mode,
          {"Mode", "scsi.spc.wb.mode", FT_UINT8, BASE_HEX,
           VALS(scsi_wb_mode_val), 0xF, NULL, HFILL}},
        { &hf_scsi_wb_bufferid,
          {"Buffer ID", "scsi.spc.sb.bufid", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_wb_bufoffset,
          {"Buffer Offset", "scsi.spc.wb.bufoff", FT_UINT24, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_paramlen24,
          {"Parameter List Length", "scsi.cdb.paramlen24", FT_UINT24, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_senddiag_st_code,
          {"Self-Test Code", "scsi.spc.senddiag.code", FT_UINT8, BASE_HEX,
           VALS(scsi_senddiag_st_code_val), 0xE0, NULL, HFILL}},
        { &hf_scsi_select_report,
          {"Select Report", "scsi.spc.select_report", FT_UINT8, BASE_HEX,
           VALS(scsi_select_report_val), 0x00, NULL, HFILL}},
        { &hf_scsi_senddiag_pf,
          {"PF", "scsi.spc.senddiag.pf", FT_BOOLEAN, 8,
           TFS(&scsi_senddiag_pf_val), 0x10, NULL, HFILL}},
        { &hf_scsi_senddiag_st,
          {"Self Test", "scsi.spc.senddiag.st", FT_BOOLEAN, 8, NULL,
           0x4, NULL, HFILL}},
        { &hf_scsi_senddiag_devoff,
          {"Device Offline", "scsi.spc.senddiag.devoff", FT_BOOLEAN, 8,
           NULL, 0x2, NULL, HFILL}},
        { &hf_scsi_senddiag_unitoff,
          {"Unit Offline", "scsi.spc.senddiag.unitoff", FT_BOOLEAN, 8,
           NULL, 0x1, NULL, HFILL}},
        { &hf_scsi_request_frame,
          { "Request in", "scsi.request_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The request to this transaction is in this frame", HFILL }},
        { &hf_scsi_time,
          { "Time from request", "scsi.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "Time between the Command and the Response", HFILL }},
        { &hf_scsi_response_frame,
          { "Response in", "scsi.response_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The response to this transaction is in this frame", HFILL }},
        { &hf_scsi_fragments,
          { "SCSI Fragments", "scsi.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_scsi_fragment_overlap,
          { "Fragment overlap", "scsi.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }},
        { &hf_scsi_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "scsi.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_scsi_fragment_multiple_tails,
          { "Multiple tail fragments found", "scsi.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_scsi_fragment_too_long_fragment,
          { "Fragment too long", "scsi.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_scsi_fragment_error,
          { "Defragmentation error", "scsi.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_scsi_fragment_count,
          { "Fragment count", "scsi.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_scsi_fragment,
          { "SCSI DATA Fragment", "scsi.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_scsi_reassembled_in,
          { "Reassembled SCSI DATA in frame", "scsi.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This SCSI DATA packet is reassembled in this frame", HFILL }},
        { &hf_scsi_reassembled_length,
          { "Reassembled SCSI DATA length", "scsi.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},
        { &hf_scsi_log_ppc_flags,
          {"PPC Flags", "scsi.log.ppc.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_ppc,
          {"PPC", "scsi.log.ppc", FT_BOOLEAN, 8,
           TFS(&scsi_log_ppc_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_log_pcr,
          {"PCR", "scsi.log.pcr", FT_BOOLEAN, 8,
           TFS(&scsi_log_pcr_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_log_sp,
          {"SP", "scsi.log.sp", FT_BOOLEAN, 8,
           TFS(&scsi_log_sp_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_log_pc_flags,
          {"PC Flags", "scsi.log.pc.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_parameter_ptr,
          {"Parameter Pointer", "scsi.log.param_ptr", FT_UINT8, BASE_HEX, NULL,
           0, NULL, HFILL}},
        { &hf_scsi_log_page_length,
          {"Page Length", "scsi.log.page_length", FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_parameter_code,
          {"Parameter Code", "scsi.log.parameter_code", FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_param_flags,
          {"Param Flags", "scsi.log.param.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_param_len,
          {"Parameter Len", "scsi.log.param_len", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_param_data,
          {"Parameter Data", "scsi.log.param_data", FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_log_pf_du,
          {"DU", "scsi.log.pf.du", FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}},
        { &hf_scsi_log_pf_ds,
          {"DS", "scsi.log.pf.ds", FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}},
        { &hf_scsi_log_pf_tsd,
          {"TSD", "scsi.log.pf.tsd", FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}},
        { &hf_scsi_log_pf_etc,
          {"ETC", "scsi.log.pf.etc", FT_BOOLEAN, 8, NULL, 0x10,
           NULL, HFILL}},
        { &hf_scsi_log_pf_tmc,
          {"TMC", "scsi.log.pf.tmc", FT_UINT8, BASE_HEX, VALS(log_flags_tmc_vals), 0x0c,
           NULL, HFILL}},
        { &hf_scsi_log_pf_lbin,
          {"LBIN", "scsi.log.pf.lbin", FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}},
        { &hf_scsi_log_pf_lp,
          {"LP", "scsi.log.pf.lp", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_rw,
          {"Read Warning", "scsi.log.ta.rw", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_ww,
          {"write warning", "scsi.log.ta.ww", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_he,
          {"hard error", "scsi.log.ta.he", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_media,
          {"media", "scsi.log.ta.media", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_rf,
          {"read failure", "scsi.log.ta.rf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_wf,
          {"write failure", "scsi.log.ta.wf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_ml,
          {"media life", "scsi.log.ta.ml", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_ndg,
          {"not data grade", "scsi.log.ta.ndg", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_wp,
          {"write protect", "scsi.log.ta.wp", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_nr,
          {"no removal", "scsi.log.ta.nr", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_cm,
          {"cleaning media", "scsi.log.ta.cm", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_uf,
          {"unsupported format", "scsi.log.ta.uf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_rmcf,
          {"removable mechanical cartridge failure", "scsi.log.ta.rmcf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_umcf,
          {"unrecoverable mechanical cartridge failure", "scsi.log.ta.umcf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_mcicf,
          {"memory chip in cartridge failure", "scsi.log.ta.mcicf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_fe,
          {"forced eject", "scsi.log.ta.fe", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_rof,
          {"read only format", "scsi.log.ta.rof", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_tdcol,
          {"tape directory corrupted on load", "scsi.log.ta.tdcol", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_nml,
          {"nearing media life", "scsi.log.ta.nml", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_cn,
          {"clean now", "scsi.log.ta.cn", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_cp,
          {"clean periodic", "scsi.log.ta.cp", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_ecm,
          {"expired cleaning media", "scsi.log.ta.ecm", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_ict,
          {"invalid cleaning tape", "scsi.log.ta.ict", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_rr,
          {"retention requested", "scsi.log.ta.rr", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_dpie,
          {"dual port interface error", "scsi.log.ta.dpie", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_cff,
          {"cooling fan failure", "scsi.log.ta.cff", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_psf,
          {"power supply failure", "scsi.log.ta.psf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_pc,
          {"power consumption", "scsi.log.ta.pc", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_dm,
          {"drive maintenance", "scsi.log.ta.dm", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_hwa,
          {"hardware a", "scsi.log.ta.hwa", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_hwb,
          {"hardware b", "scsi.log.ta.hwb", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_if,
          {"interface", "scsi.log.ta.if", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_em,
          {"eject media", "scsi.log.ta.em", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_dwf,
          {"download failed", "scsi.log.ta.dwf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_drhu,
          {"drive humidity", "scsi.log.ta.drhu", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_drtm,
          {"drive temperature", "scsi.log.ta.drtm", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_drvo,
          {"drive voltage", "scsi.log.ta.drvo", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_pefa,
          {"periodic failure", "scsi.log.ta.pefa", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_dire,
          {"diagnostics required", "scsi.log.ta.dire", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_lost,
          {"lost statistics", "scsi.log.ta.lost", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_tduau,
          {"tape directory invalid at unload", "scsi.log.ta.tduau", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_tsawf,
          {"tape system area write failure", "scsi.log.ta.tsawf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_tsarf,
          {"tape system area read failure", "scsi.log.ta.tsarf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_nsod,
          {"no start of data", "scsi.log.ta.nsod", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_lofa,
          {"loading failure", "scsi.log.ta.lofa", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_uuf,
          {"unrecoverable unload failure", "scsi.log.ta.uuf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_aif,
          {"automatic interface failure", "scsi.log.ta.aif", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_fwf,
          {"firmware failure", "scsi.log.ta.fwf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_wmicf,
          {"worm medium integrity check failed", "scsi.log.ta.wmicf", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_log_ta_wmoa,
          {"worm medium overwrite attempted", "scsi.log.ta.wmoa", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_sbc_threshold_exponent,
          {"Threshold Exponent", "scsi_sbc.threshold_exponent", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_sbc_lbpu,
          {"LBPU (logical block provisioning UNMAP)", "scsi_sbc.lbpu", FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}},
        { &hf_scsi_sbc_lbpws,
          {"LBPWS (logical block provisioning WRITE SAME)", "scsi_sbc.lbpws", FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}},
        { &hf_scsi_sbc_lbpws10,
          {"LBPWS10 (logical block provisioning WRITE SAME (10) )", "scsi_sbc.lbpws10", FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}},
        { &hf_scsi_sbc_lbprz,
          {"LBPRZ (logical block provisioning read zeros)", "scsi_sbc.lbprz", FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}},
        { &hf_scsi_sbc_anc_sup,
          {"ANC_SUP (anchor supported)", "scsi_sbc.anc_sup", FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}},
        { &hf_scsi_sbc_dp,
          {"DP (descriptor present)", "scsi_sbc.dp", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_sbc_ptype,
          {"Provisioning Type", "scsi_sbc.ptype", FT_UINT8, BASE_DEC, VALS(provisioning_vals), 0x07,
           NULL, HFILL}},
        { &hf_scsi_block_limits_wsnz,
          {"WSNZ (write same non-zero)", "scsi_sbc.bl.wsnz", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mcawl,
          {"Maximum Compare And Write Length", "scsi_sbc.bl.mcawl", FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_otlg,
          {"Optimal Transfer Length Granularity", "scsi_sbc.bl.otlg", FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mtl,
          {"Maximum Transfer Length", "scsi_sbc.bl.mtl", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_otl,
          {"Optimal Transfer Length", "scsi_sbc.bl.otl", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mpl,
          {"Optimal Prefetch/Xdread/Xdwrite Transfer Length", "scsi_sbc.bl.mpl", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mulc,
          {"Maximum Unmap LBA Count", "scsi_sbc.bl.mulc", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mubdc,
          {"Maximum Unmap Block Descriptor Count", "scsi_sbc.bl.mubdc", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_oug,
          {"Optimal Unmap Block Granularity", "scsi_sbc.bl.oug", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_ugavalid,
          {"UGAVALID", "scsi_sbc.bl.ugavalid", FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}},
        { &hf_scsi_block_limits_uga,
          {"Unmap Granularity Alignment", "scsi_sbc.bl.uga", FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
           NULL, HFILL}},
        { &hf_scsi_block_limits_mwsl,
          {"Maximum Write Same Length", "scsi_sbc.bl.mwsl", FT_UINT64, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_matl,
          {"Maximum Atomic Transfer Length", "scsi_sbc.bl.matl", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_aa,
          {"Atomic Alignment", "scsi_sbc.bl.aa", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_block_limits_atlg,
          {"Atomic Transfer Length Granularity", "scsi_sbc.bl.atlg", FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_modepage_ps,
          {"PS", "scsi.spc.modepage.ps", FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}},
        { &hf_scsi_modepage_spf,
          {"SPF", "scsi.spc.modepage.spf", FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}},
        { &hf_scsi_modepage_plen,
          {"Page Length", "scsi.spc.modepage.plen", FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_modepage_tcmos,
          {"TCMOS", "scsi.spc.modepage.tcmos", FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}},
        { &hf_scsi_modepage_scsip,
          {"SCSIP", "scsi.spc.modepage.scsip", FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}},
        { &hf_scsi_modepage_ialuae,
          {"IALUAE", "scsi.spc.modepage.ialuae", FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}},
        { &hf_scsi_modepage_icp,
          {"Initial Command Priority", "scsi.spc.modepage.icp", FT_UINT8, BASE_DEC,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_modepage_msdl,
          {"Maximum Sense Data Length", "scsi.spc.modepage.msdl", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_lun,
          { "LUN", "scsi.lun", FT_UINT16, BASE_HEX,
           NULL, 0, "Logical Unit Number", HFILL }},
        { &hf_scsi_lun_extended,
          { "LUN", "scsi.lun_long", FT_UINT64, BASE_HEX,
           NULL, 0, "Logical Unit Number", HFILL }},
        /* hf_scsi_bus has length of 0x6 with 2bit offset, or 0x3 with no offset
           so we handle it with add_bits_item */
        { &hf_scsi_bus,
          { "BUS", "scsi.bus", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL }},
        { &hf_scsi_target,
          { "Target", "scsi.target", FT_UINT8, BASE_HEX,
           NULL, 0x3f, NULL, HFILL }},
        { &hf_scsi_lun_address_mode,
          { "Address Mode", "scsi.lun.address_mode", FT_UINT8, BASE_HEX,
          VALS(scsi_lun_address_mode_vals), 0xc0, "Addressing mode for the LUN", HFILL }},
        { &hf_scsi_extended_add_method_len,
          { "Extended Address Method Length", "scsi.lun.extended_address_method.len", FT_UINT8, BASE_HEX,
          NULL, 0x30, "Extended Address Method Specific Field", HFILL }},
        { &hf_scsi_extended_add_method,
          { "Extended Address Method", "scsi.lun.extended_address_method", FT_UINT8, BASE_HEX,
          NULL, 0xf, "Extended Logical Unit Addressing", HFILL }},
        { &hf_scsi_prevent_allow_flags,
          {"Prevent Allow Flags", "scsi.prevent_allow.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_prevent_allow_prevent,
          { "PREVENT", "scsi.prevent_allow.prevent", FT_BOOLEAN, 8,
            NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mpi_service_action,
          { "Service Action", "scsi.mpi.service_action", FT_UINT8, BASE_HEX,
          VALS(mpi_action_vals), 0x1f, "Management Protocol In Service Action", HFILL }},
        { &hf_scsi_report_opcodes_rctd,
          { "RCTD", "scsi.report_opcodes.rctd", FT_BOOLEAN, 8,
            NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_report_opcodes_options,
          { "Reporting Options", "scsi.report_opcodes.options", FT_UINT8, BASE_HEX,
            VALS(report_opcodes_options_vals), 0x07, NULL, HFILL}},
        { &hf_scsi_report_opcodes_requested_o,
          { "Requested Operation Code", "scsi.report_opcodes.requested_operation_code", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_requested_sa,
          { "Requested Service Action", "scsi.report_opcodes.requested_service_action", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_cdl,
          { "Command Data Length", "scsi.report_opcodes.command_data_length", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_sa,
          { "Service Action", "scsi.report_opcodes.service_action", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_ctdp,
          { "CTDP", "scsi.report_opcodes.ctdp", FT_BOOLEAN, 8,
            NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_report_opcodes_ctdp_one,
          { "CTDP", "scsi.report_opcodes_one.ctdp", FT_BOOLEAN, 8,
            NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_report_opcodes_servactv,
          { "SERVACTV", "scsi.report_opcodes.servactv", FT_BOOLEAN, 8,
            NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_report_opcodes_cdb_length,
          { "CDB Length", "scsi.report_opcodes.cdb_length", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_support,
          { "Support", "scsi.report_opcodes.support", FT_UINT8, BASE_DEC,
            NULL, 0x07, NULL, HFILL}},
        { &hf_scsi_report_opcodes_cdb_usage_data,
          {"CDB Usage Data", "scsi.report_opcodes.cdb_usage_data", FT_BYTES, BASE_NONE,
       NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_tdl,
          { "Timeout Descriptor Length", "scsi.report_opcodes.timeout_descriptor_length", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_npt,
            { "Nominal Command Processing Timeout", "scsi.report_opcodes.ncpt", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL}},
        { &hf_scsi_report_opcodes_rct,
            { "Recommended Command Timeout", "scsi.report_opcodes.rct", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_mrr,
            { "Medium Rotation Rate", "scsi.inquiry.bdc.mrr", FT_UINT16, BASE_DEC,
                VALS(mrr_val), 0, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_pt,
            { "Product Type", "scsi.inquiry.bdc.pt", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_wabereq,
            { "WABEREQ", "scsi.inquiry.bdc.wabereq", FT_UINT8, BASE_DEC,
                NULL, 0xc0, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_wacereq,
            { "WACEREQ", "scsi.inquiry.bdc.wacereq", FT_UINT8, BASE_DEC,
                NULL, 0x30, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_nff,
          { "Nominal Form factor", "scsi.inquiry.bdc.nff", FT_UINT8, BASE_DEC,
              NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_fuab,
            { "FUAB", "scsi.inquiry.bdc.fuab", FT_BOOLEAN, 8,
                NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_inquiry_bdc_vbuls,
            { "VBULS", "scsi.inquiry.bdc.vbuls", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL}},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_scsi_inq_evpd_page_length, { "Page Length", "scsi.inquiry.evpd.pagelength", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_supported_page, { "Supported Page", "scsi.inquiry.evpd.supported_page", FT_UINT8, BASE_HEX, VALS(scsi_evpd_pagecode_val), 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_code_set, { "Code Set", "scsi.inquiry.evpd.devid.code_set", FT_UINT8, BASE_HEX, VALS(scsi_devid_codeset_val), 0x0F, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_association, { "Association", "scsi.inquiry.evpd.devid.association", FT_UINT8, BASE_HEX, VALS(scsi_devid_assoc_val), 0x30, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_identifier_type, { "Identifier Type", "scsi.inquiry.evpd.devid.identifier_type", FT_UINT8, BASE_HEX, VALS(scsi_devid_idtype_val), 0x0F, NULL, HFILL }},
      { &hf_scsi_inq_evpd_identifier_number, { "Identifier Number", "scsi.inquiry.evpd.identifier_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_identifier_length, { "Identifier Length", "scsi.inquiry.evpd.devid.identifier_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_identifier_str, { "Identifier", "scsi.inquiry.evpd.devid.identifier_str", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_devid_identifier_bytes, { "Identifier", "scsi.inquiry.evpd.devid.identifier_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_evpd_product_serial_number, { "Product Serial Number", "scsi.inquiry.evpd.product_serial_number", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_cmddt_support, { "Support", "scsi.inquiry.cmddt.support", FT_UINT8, BASE_DEC, VALS(scsi_cmdt_supp_val), 0x07, NULL, HFILL }},
      { &hf_scsi_inq_cmddt_version, { "Version", "scsi.inquiry.cmddt.version", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &scsi_verdesc_val_ext, 0x0, NULL, HFILL }},
      { &hf_scsi_inq_cmddt_cdb_size, { "CDB Size", "scsi.inquiry.cmddt.cdb_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_no_of_blocks64, { "No. of Blocks", "scsi.blockdescs.no_of_blocks64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_density_code, { "Density Code", "scsi.blockdescs.density_code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_block_length32, { "Block Length", "scsi.blockdescs.block_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_no_of_blocks32, { "No. of Blocks", "scsi.blockdescs.no_of_blocks", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_block_length24, { "Block Length", "scsi.blockdescs.block_length", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_blockdescs_no_of_blocks24, { "No. of Blocks", "scsi.blockdescs.no_of_blocks", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_gltsd, { "Global Logging Target Save Disable", "scsi.spc.modepage.gltsd", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_spc_modepage_disable_queuing, { "Disable Queuing", "scsi.spc.modepage.disable_queuing", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_spc_modepage_swp, { "SWP", "scsi.spc.modepage.swp", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_spc_modepage_autoload_mode, { "Autoload Mode", "scsi.spc.modepage.autoload_mode", FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }},
      { &hf_scsi_spc_modepage_ready_aer_holdoff_period, { "Ready AER Holdoff Period (ms)", "scsi.spc.modepage.ready_aer_holdoff_period", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_busy_timeout_period, { "Busy Timeout Period (ms)", "scsi.spc.modepage.busy_timeout_period", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_extended_self_test_completion_time, { "Extended Self-Test Completion Time", "scsi.spc.modepage.extended_self_test_completion_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_buffer_full_ratio, { "Buffer Full Ratio", "scsi.spc.modepage.buffer_full_ratio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_buffer_empty_ratio, { "Buffer Empty Ratio", "scsi.spc.modepage.buffer_empty_ratio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_bus_inactivity_limit, { "Bus Inactivity Limit", "scsi.spc.modepage.bus_inactivity_limit", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_disconnect_time_limit, { "Disconnect Time Limit", "scsi.spc.modepage.disconnect_time_limit", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_connect_time_limit, { "Connect Time Limit", "scsi.spc.modepage.connect_time_limit", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_maximum_burst_size, { "Maximum Burst Size (bytes)", "scsi.spc.modepage.maximum_burst_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_emdp, { "EMDP", "scsi.spc.modepage.emdp", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_spc_modepage_first_burst_size, { "First Burst Size (bytes)", "scsi.spc.modepage.first_burst_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_perf, { "Perf", "scsi.spc.modepage.perf", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_spc_modepage_interval_timer, { "Interval Timer", "scsi.spc.modepage.interval_timer", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_report_count, { "Report Count", "scsi.spc.modepage.report_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_idle, { "Idle", "scsi.spc.modepage.idle", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_spc_modepage_idle_condition_timer, { "Idle Condition Timer (ms)", "scsi.spc.modepage.idle_condition_timer", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_standby_condition_timer, { "Standby Condition Timer (ms)", "scsi.spc.modepage.standby_condition_timer", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_dtfd, { "DTFD", "scsi.spc.modepage.dtfd", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_spc_modepage_rr_tov_units, { "RR_TOV Units", "scsi.spc.modepage.rr_tov_units", FT_UINT8, BASE_DEC, VALS(scsi_fcp_rrtov_val), 0x07, NULL, HFILL }},
      { &hf_scsi_spc_modepage_rr_tov, { "RR_TOV", "scsi.spc.modepage.rr_tov", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_tracks_per_zone, { "Tracks Per Zone", "scsi.sbc.modepage.tracks_per_zone", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_alternate_sectors_per_zone, { "Alternate Sectors Per Zone", "scsi.sbc.modepage.alternate_sectors_per_zone", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_alternate_tracks_per_zone, { "Alternate Tracks Per Zone", "scsi.sbc.modepage.alternate_tracks_per_zone", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_alternate_tracks_per_lu, { "Alternate Tracks Per LU", "scsi.sbc.modepage.alternate_tracks_per_lu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_sectors_per_track, { "Sectors Per Track", "scsi.sbc.modepage.sectors_per_track", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_data_bytes_per_physical_sector, { "Data Bytes Per Physical Sector", "scsi.sbc.modepage.data_bytes_per_physical_sector", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_interleave, { "Interleave", "scsi.sbc.modepage.interleave", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_track_skew_factor, { "Track Skew Factor", "scsi.sbc.modepage.track_skew_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_cylinder_skew_factor, { "Cylinder Skew Factor", "scsi.sbc.modepage.cylinder_skew_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_ssec, { "SSEC", "scsi.sbc.modepage.ssec", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_awre, { "AWRE", "scsi.sbc.modepage.awre", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_read_retry_count, { "Read Retry Count", "scsi.sbc.modepage.read_retry_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_correction_span, { "Correction Span", "scsi.sbc.modepage.correction_span", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_head_offset_count, { "Head Offset Count", "scsi.sbc.modepage.head_offset_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_data_strobe_offset_count, { "Data Strobe Offset Count", "scsi.sbc.modepage.data_strobe_offset_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_write_retry_count, { "Write Retry Count", "scsi.sbc.modepage.write_retry_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_recovery_time_limit, { "Recovery Time Limit (ms)", "scsi.sbc.modepage.recovery_time_limit", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_number_of_cylinders, { "Number of Cylinders", "scsi.sbc.modepage.number_of_cylinders", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_number_of_heads, { "Number of Heads", "scsi.sbc.modepage.number_of_heads", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_starting_cyl_pre_compensation, { "Starting Cyl Pre-compensation", "scsi.sbc.modepage.starting_cyl_pre_compensation", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_starting_cyl_reduced_write_current, { "Starting Cyl-reduced Write Current", "scsi.sbc.modepage.starting_cyl_reduced_write_current", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_device_step_rate, { "Device Step Rate", "scsi.sbc.modepage.device_step_rate", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_landing_zone_cyl, { "Landing Zone Cyl", "scsi.sbc.modepage.landing_zone_cyl", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_rotational_offset, { "Rotational Offset", "scsi.sbc.modepage.rotational_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_medium_rotation_rate, { "Medium Rotation Rate", "scsi.sbc.modepage.medium_rotation_rate", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_ic, { "IC", "scsi.sbc.modepage.ic", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_demand_read_retention_priority, { "Demand Read Retention Priority", "scsi.sbc.modepage.demand_read_retention_priority", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_disable_pre_fetch_xfer_len, { "Disable Pre-fetch Xfer Len", "scsi.sbc.modepage.disable_pre_fetch_xfer_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_minimum_pre_fetch, { "Minimum Pre-Fetch", "scsi.sbc.modepage.minimum_pre_fetch", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_maximum_pre_fetch, { "Maximum Pre-Fetch", "scsi.sbc.modepage.maximum_pre_fetch", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_maximum_pre_fetch_ceiling, { "Maximum Pre-Fetch Ceiling", "scsi.sbc.modepage.maximum_pre_fetch_ceiling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_fsw, { "FSW", "scsi.sbc.modepage.fsw", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_number_of_cache_segments, { "Number of Cache Segments", "scsi.sbc.modepage.number_of_cache_segments", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_cache_segment_size, { "Cache Segment Size", "scsi.sbc.modepage.cache_segment_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_non_cache_segment_size, { "Non-Cache Segment Size", "scsi.sbc.modepage.non_cache_segment_size", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_dce, { "DCE", "scsi.ssc2.modepage.dce", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_dde, { "DDE", "scsi.ssc2.modepage.dde", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_compression_algorithm, { "Compression algorithm", "scsi.ssc2.modepage.compression_algorithm", FT_UINT32, BASE_HEX, VALS(compression_algorithm_vals), 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_decompression_algorithm, { "Decompression algorithm", "scsi.ssc2.modepage.decompression_algorithm", FT_UINT32, BASE_HEX, VALS(compression_algorithm_vals), 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_caf, { "CAF", "scsi.ssc2.modepage.caf", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_active_partition, { "Active Partition", "scsi.ssc2.modepage.active_partition", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_write_object_buffer_full_ratio, { "Write Object Buffer Full Ratio", "scsi.ssc2.modepage.write_object_buffer_full_ratio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_read_object_buffer_empty_ratio, { "Read Object Buffer Empty Ratio", "scsi.ssc2.modepage.read_object_buffer_empty_ratio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_write_delay_time, { "Write Delay time", "scsi.ssc2.modepage.write_delay_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_obr, { "OBR", "scsi.ssc2.modepage.obr", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_gap_size, { "Gap Size", "scsi.ssc2.modepage.gap_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_eod_defined, { "EOD Defined", "scsi.ssc2.modepage.eod_defined", FT_UINT8, BASE_DEC, NULL, 0xE0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_object_buffer_size_at_early_warning, { "Object Buffer Size At Early Warning", "scsi.ssc2.modepage.object_buffer_size_at_early_warning", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_select_data_compression_algorithm, { "Select Data Compression Algorithm", "scsi.ssc2.modepage.select_data_compression_algorithm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_oir, { "OIR", "scsi.ssc2.modepage.oir", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_maximum_additional_partitions, { "Maximum Additional Partitions", "scsi.ssc2.modepage.maximum_additional_partitions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_additional_partitions_defined, { "Additional Partitions Defined", "scsi.ssc2.modepage.additional_partitions_defined", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_fdp, { "FDP", "scsi.ssc2.modepage.fdp", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_media_format_recognition, { "Media Format Recognition", "scsi.ssc2.modepage.media_format_recognition", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_partition_units, { "Partition Units", "scsi.ssc2.modepage.partition_units", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_partition_size, { "Partition Size", "scsi.ssc2.modepage.partition_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_lba_space, { "LBA Space", "scsi.mmc5.modepage.lba_space", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_bufe, { "BUFE", "scsi.mmc5.modepage.bufe", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_wrparam_multi_session, { "Multi-session", "scsi.mmc5.modepage.wrparam_multi_session", FT_UINT8, BASE_DEC, NULL, 0xC0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_data_block_type, { "Data Block Type", "scsi.mmc5.modepage.data_block_type", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_link_size, { "Link Size", "scsi.mmc5.modepage.link_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_initiator_application_code, { "Initiator Application Code", "scsi.mmc5.modepage.initiator_application_code", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_session_format, { "Session Format", "scsi.mmc5.modepage.session_format", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_packet_size, { "Packet Size", "scsi.mmc5.modepage.packet_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_audio_pause_length, { "Audio Pause Length", "scsi.mmc5.modepage.audio_pause_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_media_catalog_number, { "Media Catalog Number", "scsi.mmc5.modepage.media_catalog_number", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_international_standard_recording_code, { "International Standard Recording Code", "scsi.mmc5.modepage.international_standard_recording_code", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_sub_header_byte, { "Sub-header Byte", "scsi.mmc5.modepage.sub_header_byte", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_vendor_specific, { "Vendor Specific", "scsi.mmc5.modepage.vendor_specific", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_ram_read, { "DVD-RAM Read", "scsi.mmc5.modepage.dvd_ram_read", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_ram_write, { "DVD-RAM Write", "scsi.mmc5.modepage.dvd_ram_write", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_buf, { "BUF", "scsi.mmc5.modepage.buf", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_read_bar_code, { "Read Bar Code", "scsi.mmc5.modepage.read_bar_code", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_loading_mechanism_type, { "Loading Mechanism Type", "scsi.mmc5.modepage.loading_mechanism_type", FT_UINT8, BASE_DEC, NULL, 0xE0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_rw_in_lead_in, { "R-W in Lead-in", "scsi.mmc5.modepage.rw_in_lead_in", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_number_of_volume_levels_supported, { "Number of Volume Levels Supported", "scsi.mmc5.modepage.number_of_volume_levels_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_buffer_size_supported, { "Buffer Size Supported", "scsi.mmc5.modepage.buffer_size_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_length, { "Length", "scsi.mmc5.modepage.length", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_copy_management_revision_support, { "Copy Management Revision Support", "scsi.mmc5.modepage.copy_management_revision_support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_rotation_control_selected, { "Rotation Control Selected", "scsi.mmc5.modepage.rotation_control_selected", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_current_write_speed_selected, { "Current Write Speed Selected", "scsi.mmc5.modepage.current_write_speed_selected", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_num_write_speed_performance, { "Number of Logical Unit Write Speed Performance Descriptor Tables", "scsi.mmc5.modepage.num_write_speed_performance", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_first_medium_transport_element_address, { "First Medium Transport Element Address", "scsi.mode.smc.first_medium_transport_element_address", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_number_of_medium_transport_elements, { "Number of Medium Transport Elements", "scsi.mode.smc.number_of_medium_transport_elements", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_first_storage_element_address, { "First Storage Element Address", "scsi.mode.smc.first_storage_element_address", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_number_of_storage_elements, { "Number of Storage Elements", "scsi.mode.smc.number_of_storage_elements", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_first_import_export_element_address, { "First Import/Export Element Address", "scsi.mode.smc.first_import_export_element_address", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_number_of_import_export_elements, { "Number of Import/Export Elements", "scsi.mode.smc.number_of_import_export_elements", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_first_data_transfer_element_address, { "First Data Transfer Element Address", "scsi.mode.smc.first_data_transfer_element_address", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_number_of_data_transfer_elements, { "Number of Data Transfer Elements", "scsi.mode.smc.number_of_data_transfer_elements", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_smc_modepage_stordt, { "STORDT", "scsi.mode.smc.stordt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_dt, { "MT->DT", "scsi.mode.smc.mt_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_dt, { "ST->DT", "scsi.mode.smc.st_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_dt, { "I/E->DT", "scsi.mode.smc.ie_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_dt, { "DT->DT", "scsi.mode.smc.dt_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_ne_dt, { "MT<>DT", "scsi.mode.smc.mt_ne_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_ne_dt, { "ST<>DT", "scsi.mode.smc.st_ne_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_ne_dt, { "I/E<>DT", "scsi.mode.smc.ie_ne_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_ne_dt, { "DT<>DT", "scsi.mode.smc.dt_ne_dt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_modesel_mode_data_length8, { "Mode Data Length", "scsi.cdb.mode.mode_data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_dev_sbc_medium_type, { "Medium Type", "scsi.cdb.mode.medium_type", FT_UINT8, BASE_HEX, VALS(scsi_modesense_medtype_sbc_val), 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_medium_type, { "Medium Type", "scsi.cdb.mode.medium_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_device_specific_parameter, { "Device-Specific Parameter", "scsi.cdb.mode.device_specific_parameter", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_block_descriptor_length8, { "Block Descriptor Length", "scsi.cdb.mode.block_descriptor_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_mode_data_length16, { "Mode Data Length", "scsi.cdb.mode.mode_data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_modesel_longlba, { "LongLBA", "scsi.cdb.mode.longlba", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_modesel_block_descriptor_length16, { "Block Descriptor Length", "scsi.cdb.mode.block_descriptor_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_persresvin_generation_number, { "Generation Number", "scsi.persresvin.generation_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_persresvin_additional_length, { "Additional Length", "scsi.persresvin.additional_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reportluns_lun_list_length, { "LUN List Length", "scsi.reportluns.lun_list_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sns_valid, { "Valid", "scsi.sns.valid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_sns_filemark, { "Filemark", "scsi.sns.filemark", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_scsi_sns_command_specific_information, { "Command-Specific Information", "scsi.sns.command_specific_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_modepage_report_log_exception_condition, { "Report Log Exception Condition", "scsi.spc.modepage.report_log_exception_condition", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_spc_modepage_faa, { "FAA", "scsi.spc.modepage.faa", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_spc_modepage_fab, { "FAB", "scsi.spc.modepage.fab", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_spc_modepage_fac, { "FAC", "scsi.spc.modepage.fac", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_spc_modepage_ebf, { "EBF", "scsi.spc.modepage.ebf", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_spc_modepage_ewasc, { "EWasc", "scsi.spc.modepage.ewasc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_spc_modepage_dexcpt, { "DExcpt", "scsi.spc.modepage.dexcpt", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_spc_modepage_test, { "Test", "scsi.spc.modepage.test", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_spc_modepage_logerr, { "LogErr", "scsi.spc.modepage.logerr", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_spc_modepage_standby, { "Standby", "scsi.spc.modepage.standby", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_spc_modepage_plpb, { "PLPB", "scsi.spc.modepage.plpb", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_spc_modepage_ddis, { "DDIS", "scsi.spc.modepage.ddis", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_spc_modepage_dlm, { "DLM", "scsi.spc.modepage.dlm", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_spc_modepage_rha, { "RHA", "scsi.spc.modepage.rha", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_spc_modepage_alwi, { "ALWI", "scsi.spc.modepage.alwi", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_spc_modepage_dtipe, { "DTIPE", "scsi.spc.modepage.dtipe", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_spc_modepage_dtoli, { "DTOLI", "scsi.spc.modepage.dtoli", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_hsec, { "HSEC", "scsi.sbc.modepage.hsec", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_rmb, { "RMB", "scsi.sbc.modepage.rmb", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_surf, { "SURF", "scsi.sbc.modepage.surf", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_arre, { "ARRE", "scsi.sbc.modepage.arre", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_tb, { "TB", "scsi.sbc.modepage.tb", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_rc, { "RC", "scsi.sbc.modepage.rc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_eer, { "EER", "scsi.sbc.modepage.eer", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_per, { "PER", "scsi.sbc.modepage.per", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_dte, { "DTE", "scsi.sbc.modepage.dte", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_dcr, { "DCR", "scsi.sbc.modepage.dcr", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_abpf, { "ABPF", "scsi.sbc.modepage.abpf", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_cap, { "CAP", "scsi.sbc.modepage.cap", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_disc, { "Disc", "scsi.sbc.modepage.disc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_size, { "Size", "scsi.sbc.modepage.size", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_wce, { "WCE", "scsi.sbc.modepage.wce", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_mf, { "MF", "scsi.sbc.modepage.mf", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_rcd, { "RCD", "scsi.sbc.modepage.rcd", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_write_retention_priority, { "Write Retention Priority", "scsi.sbc.modepage.write_retention_priority", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_lbcss, { "LBCSS", "scsi.sbc.modepage.lbcss", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_dra, { "DRA", "scsi.sbc.modepage.dra", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_sbc_modepage_vendor_specific, { "Vendor Specific", "scsi.sbc.modepage.vendor_specific", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_dcc, { "DCC", "scsi.ssc2.modepage.dcc", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_red, { "RED", "scsi.ssc2.modepage.red", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_active_format, { "Active Format", "scsi.ssc2.modepage.active_format", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_lois, { "LOIS", "scsi.ssc2.modepage.lois", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_rsmk, { "RSMK", "scsi.ssc2.modepage.rsmk", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_avc, { "AVC", "scsi.ssc2.modepage.avc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_socf, { "SOCF", "scsi.ssc2.modepage.socf", FT_UINT8, BASE_DEC, NULL, 0x0C, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_robo, { "ROBO", "scsi.ssc2.modepage.robo", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_rew, { "REW", "scsi.ssc2.modepage.rew", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_eeg, { "EEG", "scsi.ssc2.modepage.eeg", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_sew, { "SEW", "scsi.ssc2.modepage.sew", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_swp, { "SWP", "scsi.ssc2.modepage.swp", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_baml, { "BAML", "scsi.ssc2.modepage.baml", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_bam, { "BAM", "scsi.ssc2.modepage.bam", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_rewind_on_reset, { "ReWind on Reset", "scsi.ssc2.modepage.rewind_on_reset", FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_asocwp, { "ASOCWP", "scsi.ssc2.modepage.asocwp", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_perswp, { "PERSWP", "scsi.ssc2.modepage.perswp", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_prmwp, { "PRMWP", "scsi.ssc2.modepage.prmwp", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_dsp, { "DSP", "scsi.ssc2.modepage.dsp", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_idp, { "IDP", "scsi.ssc2.modepage.idp", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_psum, { "PSUM", "scsi.ssc2.modepage.psum", FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_pofm, { "POFM", "scsi.ssc2.modepage.pofm", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_clear, { "CLEAR", "scsi.ssc2.modepage.clear", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_ssc2_modepage_addp, { "ADDP", "scsi.ssc2.modepage.addp", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_ls_v, { "LS_V", "scsi.mmc5.modepage.ls_v", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_wrparam_test_write, { "Test Write", "scsi.mmc5.modepage.wrparam_test_write", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_write_type, { "Write Type", "scsi.mmc5.modepage.write_type", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_fp, { "FP", "scsi.mmc5.modepage.fp", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_copy, { "Copy", "scsi.mmc5.modepage.copy", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_track_mode, { "Track Mode", "scsi.mmc5.modepage.track_mode", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_r_read, { "DVD-R Read", "scsi.mmc5.modepage.dvd_r_read", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_rom_read, { "DVD-ROM Read", "scsi.mmc5.modepage.dvd_rom_read", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_method_2, { "Method 2", "scsi.mmc5.modepage.method_2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_rw_read, { "CD-RW Read", "scsi.mmc5.modepage.cd_rw_read", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_r_read, { "CD-R Read", "scsi.mmc5.modepage.cd_r_read", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_r_write, { "DVD-R Write", "scsi.mmc5.modepage.dvd_r_write", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_dvd_rom_write, { "DVD-ROM Write", "scsi.mmc5.modepage.dvd_rom_write", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_mmcap_test_write, { "Test Write", "scsi.mmc5.modepage.mmcap_test_write", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_rw_write, { "CD-RW Write", "scsi.mmc5.modepage.cd_rw_write", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_r_write, { "CD-R Write", "scsi.mmc5.modepage.cd_r_write", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_mmcap_multi_session, { "Multi Session", "scsi.mmc5.modepage.mmcap_multi_session", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_mode_2_form2, { "Mode 2 Form 2", "scsi.mmc5.modepage.mode_2_form2", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_mode_2_form1, { "Mode 2 Form 1", "scsi.mmc5.modepage.mode_2_form1", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_digital_port2, { "Digital Port (2)", "scsi.mmc5.modepage.digital_port2", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_digital_port1, { "Digital Port (1)", "scsi.mmc5.modepage.digital_port1", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_composite, { "Composite", "scsi.mmc5.modepage.composite", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_audio_play, { "Audio Play", "scsi.mmc5.modepage.audio_play", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_upc, { "UPC", "scsi.mmc5.modepage.upc", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_isrc, { "ISRC", "scsi.mmc5.modepage.isrc", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_c2_pointers_supported, { "C2 Pointers supported", "scsi.mmc5.modepage.c2_pointers_supported", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_rw_deinterleaved_corrected, { "R-W Deinterleaved & corrected", "scsi.mmc5.modepage.rw_deinterleaved_corrected", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_rw_supported, { "R-W Supported", "scsi.mmc5.modepage.rw_supported", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_da_stream_is_accurate, { "CD-DA Stream is Accurate", "scsi.mmc5.modepage.cd_da_stream_is_accurate", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_cd_da_cmds_supported, { "CD-DA Cmds Supported", "scsi.mmc5.modepage.cd_da_cmds_supported", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_eject, { "Eject", "scsi.mmc5.modepage.eject", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_prevent_jumper, { "Prevent Jumper", "scsi.mmc5.modepage.prevent_jumper", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_lock_state, { "Lock State", "scsi.mmc5.modepage.lock_state", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_lock, { "Lock", "scsi.mmc5.modepage.lock", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_side_change_capable, { "Side Change Capable", "scsi.mmc5.modepage.side_change_capable", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_sw_slot_selection, { "S/W Slot Selection", "scsi.mmc5.modepage.sw_slot_selection", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_changer_supports_disc_present, { "Changer Supports Disc Present", "scsi.mmc5.modepage.changer_supports_disc_present", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_separate_channel_mute, { "Separate Channel Mute", "scsi.mmc5.modepage.separate_channel_mute", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_separate_volume_levels, { "Separate volume levels", "scsi.mmc5.modepage.separate_volume_levels", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_lsbf, { "LSBF", "scsi.mmc5.modepage.lsbf", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_rck, { "RCK", "scsi.mmc5.modepage.rck", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_mmc5_modepage_bckf, { "BCKF", "scsi.mmc5.modepage.bckf", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_storie, { "STORI/E", "scsi.mode.smc.storie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_storst, { "STORST", "scsi.mode.smc.storst", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_stormt, { "STORMT", "scsi.mode.smc.stormt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_ie, { "MT->I/E", "scsi.mode.smc.mt_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_st, { "MT->ST", "scsi.mode.smc.mt_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_mt, { "MT->MT", "scsi.mode.smc.mt_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_ie, { "ST->I/E", "scsi.mode.smc.st_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_st, { "ST->ST", "scsi.mode.smc.st_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_mt, { "ST->MT", "scsi.mode.smc.st_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_ie, { "I/E->I/E", "scsi.mode.smc.ie_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_st, { "I/E->ST", "scsi.mode.smc.ie_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_mt, { "I/E->MT", "scsi.mode.smc.ie_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_ie, { "DT->I/E", "scsi.mode.smc.dt_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_st, { "DT->ST", "scsi.mode.smc.dt_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_mt, { "DT->MT", "scsi.mode.smc.dt_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_ne_ie, { "MT<>I/E", "scsi.mode.smc.mt_ne_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_ne_st, { "MT<>ST", "scsi.mode.smc.mt_ne_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_mt_ne_mt, { "MT<>MT", "scsi.mode.smc.mt_ne_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_ne_ie, { "ST<>I/E", "scsi.mode.smc.st_ne_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_ne_st, { "ST<>ST", "scsi.mode.smc.st_ne_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_st_ne_mt, { "ST<>MT", "scsi.mode.smc.st_ne_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_ne_ie, { "I/E<>I/E", "scsi.mode.smc.ie_ne_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_ne_st, { "I/E<>ST", "scsi.mode.smc.ie_ne_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_ie_ne_mt, { "I/E<>MT", "scsi.mode.smc.ie_ne_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_ne_ie, { "DT<>I/E", "scsi.mode.smc.dt_ne_ie", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_ne_st, { "DT<>ST", "scsi.mode.smc.dt_ne_st", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
      { &hf_scsi_smc_modepage_dt_ne_mt, { "DT<>MT", "scsi.mode.smc.dt_ne_mt", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
      { &hf_scsi_sns_eom, { "EOM", "scsi.sns.eom", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_scsi_sns_ili, { "ILI", "scsi.sns.ili", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_service, { "Service action", "scsi.extcopy.service_action", FT_UINT8, BASE_HEX, VALS(extcopy_service_vals), 0x0, NULL, HFILL }},
      { &hf_scsi_spc_recv_copy_service, { "Service action", "scsi.recv_copy.service_action", FT_UINT8, BASE_HEX, VALS(recv_copy_service_vals), 0x1F, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_list_len, { "Parameter list length (bytes)", "scsi.extcopy.param_list_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_list_format, { "List format", "scsi.extcopy.list_format", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_head_cscd_desc_list_len, { "Header cscd descriptor list length", "scsi.extcopy.hdr_cscd_list_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_list_len, { "CSCD descriptor list length", "scsi.extcopy.cscd_list_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_inline_data_len, { "Inline data length", "scsi.extcopy.inline_data_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_desc_list_len, { "Segment descriptor list length", "scsi.extcopy.seg_desc_list_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_list_id, { "List ID", "scsi.extcopy.list_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_head_cscd_desc_type_code, { "Header CSCD description type code", "scsi.extcopy.head_cscd_desc_type_code", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_type_code, { "CSCD description type code", "scsi.cscd_desc_type_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(desc_type_rval), 0x0, NULL, HFILL}},
      { &hf_scsi_spc_xcopy_rel_init_port_id, { "Relative Initiator Port ID", "scsi.extcopy.rel_init_port_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_per_dev_type, { "Peripherial Device Type", "scsi.extcopy.per_dev_type", FT_UINT8, BASE_DEC, VALS(per_dev_type_vals), 0x1F, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_lu_type, { "LU type", "scsi.extcopy.lu_type", FT_UINT8, BASE_DEC, VALS(lu_type_vals), 0xC0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_per_dev_type_byte, { "Peripherial Device Type bits", "scsi.extcopy.per_dev_type_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_disk_block_len, { "Disk block length", "scsi.extcopy.disk_block_len", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_code_set, { "CSCD descriptor code set", "scsi.extcopy.cscd_code_set", FT_UINT8, BASE_DEC, VALS(scsi_devid_codeset_val), 0x0F, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_assoc, { "CSCD descriptor association", "scsi.extcopy.cscd_assoc", FT_UINT8, BASE_DEC, VALS(scsi_devid_assoc_val), 0x30, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_des_type, { "CSCD descriptor designator type", "scsi.extcopy.cscd_des_type", FT_UINT8, BASE_DEC, VALS(scsi_devid_idtype_val), 0x0F, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_cscd_desc_des_len, { "CSCD descriptor desginator length", "scsi.extcopy.cscd_des_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_desc_type, { "Segment descriptor type code", "scsi.extcopy.seg_desc_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(desc_type_rval), 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_desc_dc, { "Segment descriptor designation count bit", "scsi.extcopy.seg_desc_dc", FT_UINT8, BASE_DEC, NULL, 0x2, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_desc_cat, { "Segment descriptor CAT bit", "scsi.extcopy.seg_desc_cat", FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_des_src_desc_id, { "Segment descriptor source ID", "scsi.extcopy.seg_desc_src_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_seg_des_dest_desc_id, { "Segment descriptor destination ID", "scsi.extcopy.seg_desc_dest_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_num_of_blocks, { "Number of blocks", "scsi.extcopy.seg_desc_num_of_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_list_id_usage, { "List ID usage", "scsi.extcopy.xcopy_param_list_id_usage", FT_UINT8, BASE_HEX, NULL, 0x18, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_str, { "Sequential strip bit (str)", "scsi.extcopy.xcopy_param_str", FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_priority, { "Priority", "scsi.extcopy.xcopy_param_priority", FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_param_byte, { "Extended copy Parameters: str, list ID usage, priority", "scsi.extcopy.xcopy_params_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_source_lba, { "Source LBA", "scsi.extcopy.source_lba", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_spc_xcopy_dest_lba, { "Destination LBA", "scsi.extcopy.dest_lba", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_cscd_desc_count, { "Max. CSCD descriptors count", "scsi.recv_copy.max_cscd_desc_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_seg_desc_count, { "Max. segment descriptors count", "scsi.recv_copy.max_seg_desc_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_desc_list_len, { "Max. descriptor list length", "scsi.recv_copy.max_desc_list_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_seg_len, { "Max. segment length", "scsi.recv_copy.max_seg_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_inline_data_len, { "Max. inline data length",  "scsi.recv_copy.max_inline_data_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_held_data_limit, { "Held data limit", "scsi.recv_copy.max_held_data_limit", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_stream_dev_trans_size, { "Max. stream device transfer size", "scsi.recv_copy.max_stream_dev_trans_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_snlid, { "SNLID bit", "scsi.recv_copy.snlid", FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL }},
      { &hf_scsi_recv_copy_avail_data, { "Available data", "scsi.recv_copy.avail_data", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_total_con_copies, { "Total number of concurrent copies", "scsi.recv_copy.total_con_copies", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_max_con_copies, { "Max. number of concurrent copies", "scsi.recv_copy.max_con_copies", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_data_seg_gran, { "Data segment granularity", "scsi.recv_copy.data_seg_gran", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_inline_data_gran, { "Inline data granularity", "scsi.recv_copy.inline_data_gran", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_held_data_gran, { "Held data granularity", "scsi.recv_copy.held_data_gran", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_recv_copy_implemented_desc_list_len, { "Implemented description list length", "scsi.recv_copy.implemented_desc_list_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_designator, { "Designator", "scsi.designator", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_segment_descriptor_length, { "Segment descriptor length (bytes)", "scsi.segment_descriptor_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_inline_data, { "Inline data", "scsi.inline_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reserved_8, { "Reserved (1 byte)", "scsi.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reserved_16, { "Reserved (2 bytes)", "scsi.reserved2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reserved_24, { "Reserved (3 bytes)", "scsi.reserved3", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reserved_32, { "Reserved (4 bytes)", "scsi.reserved4", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_reserved_64, { "Reserved (8 bytes)", "scsi.reserved8", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_naa_type, { "NAA Designator Type", "scsi.naa.type", FT_UINT8, BASE_DEC, VALS(scsi_naa_designator_type_val), 0xF0, NULL, HFILL }},
      { &hf_scsi_naa_locally_assigned, { "Locally Assigned", "scsi.naa.locally_assigned", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_naa_ieee_company_id, { "IEEE Company ID", "scsi.naa.ieee_company_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_naa_vendor_specific, { "Vendor Specific Identifier", "scsi.naa.vendor_specific", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_scsi_naa_vendor_specific_extension, { "Vendor Specific Identifier Extension", "scsi.naa.vendor_specific.extension", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scsi,
        &ett_scsi_page,
        &ett_scsi_control,
        &ett_scsi_inq_control,
        &ett_scsi_inq_peripheral,
        &ett_scsi_inq_acaflags,
        &ett_scsi_inq_rmbflags,
        &ett_scsi_inq_sccsflags,
        &ett_scsi_inq_bqueflags,
        &ett_scsi_inq_reladrflags,
        &ett_scsi_log,
        &ett_scsi_log_ppc,
        &ett_scsi_log_pc,
        &ett_scsi_log_param,
        &ett_scsi_fragments,
        &ett_scsi_fragment,
        &ett_persresv_control,
        &ett_scsi_lun,
        &ett_scsi_lun_unit,
        &ett_scsi_prevent_allow,
        &ett_command_descriptor,
        &ett_timeout_descriptor,
        &ett_sense_descriptor,
        &ett_sense_osd_not_initiated,
        &ett_sense_osd_completed,
        &ett_xcopy_per_dev_type,
        &ett_scsi_xcopy_dev_params,
        &ett_scsi_xcopy_cscds,
        &ett_scsi_xcopy_cscd,
        &ett_scsi_xcopy_segs,
        &ett_scsi_xcopy_seg,
        &ett_scsi_xcopy_seg_param,
        &ett_xcopy_param_byte,
        &ett_scsi_cscd_desc,
        &ett_scsi_designation_descriptor,
        &ett_scsi_naa,
    };

    static ei_register_info ei[] = {
        { &ei_scsi_product_data_goes_past_end_of_page, { "scsi.product_data_goes_past_end_of_page", PI_MALFORMED, PI_WARN, "Product data goes past end of page", EXPFILL }},
        { &ei_scsi_unknown_page, { "scsi.unknown_page", PI_UNDECODED, PI_WARN, "Unknown Page", EXPFILL }},
        { &ei_scsi_no_dissection_for_service_action, { "scsi.no_dissection_for_service_action", PI_UNDECODED, PI_WARN, "No dissection for this service action yet", EXPFILL }},
        { &ei_scsi_unknown_scsi_exchange, { "scsi.unknown_scsi_exchange", PI_PROTOCOL, PI_WARN, "Unknown SCSI exchange, can not decode SCSI data", EXPFILL }},
        { &ei_scsi_unknown_serv_action, { "scsi.unknown_serv_action", PI_PROTOCOL, PI_WARN, "Unknown serv_action", EXPFILL }},
    };

    module_t *scsi_module;
    expert_module_t* expert_scsi;

    /* Register the protocol name and description */
    proto_scsi = proto_register_protocol("SCSI", "SCSI", "scsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_scsi = expert_register_protocol(proto_scsi);
    expert_register_field_array(expert_scsi, ei, array_length(ei));

    /* add preferences to decode SCSI message */
    scsi_module = prefs_register_protocol(proto_scsi, NULL);
    prefs_register_enum_preference(scsi_module, "decode_scsi_messages_as",
                                   "Decode SCSI Messages As",
                                   "When Target Cannot Be Identified, Decode SCSI Messages As",
                                   &scsi_def_devtype,
                                   scsi_devtype_options,
                                   FALSE);

    prefs_register_bool_preference(scsi_module, "defragment",
                                   "Reassemble fragmented SCSI DATA IN/OUT transfers",
                                   "Whether fragmented SCSI DATA IN/OUT transfers should be reassembled",
                                   &scsi_defragment);
    register_init_routine(scsi_defragment_init);
    register_cleanup_routine(scsi_defragment_cleanup);

    register_srt_table(proto_scsi, NULL, 1, scsistat_packet, scsistat_init, scsistat_param);

    scsi_tap    = register_tap("scsi");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
