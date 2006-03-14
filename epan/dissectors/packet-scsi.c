/* packet-scsi.c
 * Routines for decoding SCSI CDBs and responses
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Some Notes on using the SCSI Decoder:
 *
 * The SCSI decoder has been built right now that it is invoked directly by the
 * SCSI transport layers as compared to the standard mechanism of being invoked
 * via a dissector chain. There are multiple reasons for this:
 * - The SCSI CDB is typically embedded inside the transport along with other
 *   header fields that have nothing to do with SCSI. So, it is required to be
 *   invoked on a embedded subset of the packet.
 * - Originally, Ethereal couldn't do filtering on protocol trees that were not
 *   on the top level.
 *
 * There are four main routines that are provided:
 * o dissect_scsi_cdb - invoked on receiving a SCSI Command
 *   void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *,
 *   guint, guint16);
 * o dissect_scsi_payload - invoked to decode SCSI responses
 *   void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *, guint,
 *                              gboolean, guint32, guint16);
 *   The final parameter is the length of the response field that is negotiated
 *   as part of the SCSI transport layer. If this is not tracked by the
 *   transport, it can be set to 0.
 * o dissect_scsi_rsp - invoked to destroy the data structures associated with a
 *                      SCSI task.
 *   void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *, guint16,
 *                          guint8);
 * o dissect_scsi_snsinfo - invoked to decode the sense data provided in case of
 *                          an error.
 *   void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint,
 *   guint, guint16);
 *
 * In addition to this, the other requirement made from the transport is to
 * provide a unique way to determine a SCSI task. In Fibre Channel networks,
 * this is the exchange ID pair alongwith the source/destination addresses; in
 * iSCSI it is the initiator task tag along with the src/dst address and port
 * numbers. This is to be provided to the SCSI decoder via the private_data
 * field in the packet_info data structure. The private_data field is treated
 * as a pointer to a "scsi_task_id_t" structure, containing a conversation
 * ID (a number uniquely identifying a conversation between a particular
 * initiator and target, e.g. between two Fibre Channel addresses or between
 * two TCP address/port pairs for iSCSI or NDMP) and a task ID (a number
 * uniquely identifying a task within that conversation).
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-scsi.h"

static int proto_scsi                    = -1;
static int hf_scsi_lun                   = -1;
static int hf_scsi_status                = -1;
static int hf_scsi_spcopcode             = -1;
static int hf_scsi_mmcopcode             = -1;
static int hf_scsi_sbcopcode             = -1;
static int hf_scsi_sscopcode             = -1;
static int hf_scsi_smcopcode             = -1;
static int hf_scsi_control               = -1;
static int hf_scsi_inquiry_flags         = -1;
static int hf_scsi_inquiry_evpd_page     = -1;
static int hf_scsi_inquiry_cmdt_page     = -1;
static int hf_scsi_alloclen              = -1;
static int hf_scsi_logsel_flags          = -1;
static int hf_scsi_logsel_pc             = -1;
static int hf_scsi_paramlen              = -1;
static int hf_scsi_logsns_flags          = -1;
static int hf_scsi_logsns_pc             = -1;
static int hf_scsi_logsns_pagecode       = -1;
static int hf_scsi_paramlen16            = -1;
static int hf_scsi_modesel_flags         = -1;
static int hf_scsi_alloclen16            = -1;
static int hf_scsi_modesns_pc            = -1;
static int hf_scsi_spcpagecode           = -1;
static int hf_scsi_sbcpagecode           = -1;
static int hf_scsi_sscpagecode           = -1;
static int hf_scsi_smcpagecode           = -1;
static int hf_scsi_mmcpagecode           = -1;
static int hf_scsi_modesns_flags         = -1;
static int hf_scsi_persresvin_svcaction  = -1;
static int hf_scsi_persresvout_svcaction = -1;
static int hf_scsi_persresv_scope        = -1;
static int hf_scsi_persresv_type         = -1;
static int hf_scsi_release_flags         = -1;
static int hf_scsi_release_thirdpartyid  = -1;
static int hf_scsi_alloclen32            = -1;
static int hf_scsi_select_report         = -1;
static int hf_scsi_formatunit_flags      = -1;
static int hf_scsi_formatunit_interleave = -1;
static int hf_scsi_formatunit_vendor     = -1;
static int hf_scsi_rdwr6_lba             = -1;
static int hf_scsi_rdwr6_xferlen         = -1;
static int hf_scsi_rdwr10_lba            = -1;
static int hf_scsi_read_flags            = -1;
static int hf_scsi_rdwr12_xferlen        = -1;
static int hf_scsi_rdwr16_lba            = -1;
static int hf_scsi_readcapacity_flags    = -1;
static int hf_scsi_readcapacity_lba      = -1;
static int hf_scsi_readcapacity_pmi      = -1;
static int hf_scsi_rdwr10_xferlen        = -1;
static int hf_scsi_readdefdata_flags     = -1;
static int hf_scsi_cdb_defectfmt         = -1;
static int hf_scsi_reassignblks_flags    = -1;
static int hf_scsi_inq_qualifier         = -1;
static int hf_scsi_inq_devtype           = -1;
static int hf_scsi_inq_rmb		 = -1;
static int hf_scsi_inq_version           = -1;
static int hf_scsi_rluns_lun             = -1;
static int hf_scsi_rluns_multilun        = -1;
static int hf_scsi_modesns_errrep        = -1;
static int hf_scsi_modesns_tst           = -1;
static int hf_scsi_modesns_qmod          = -1;
static int hf_scsi_modesns_qerr          = -1;
static int hf_scsi_modesns_rac           = -1;
static int hf_scsi_modesns_tas           = -1;
static int hf_scsi_protocol              = -1;
static int hf_scsi_sns_errtype           = -1;
static int hf_scsi_snskey                = -1;
static int hf_scsi_snsinfo               = -1;
static int hf_scsi_addlsnslen            = -1;
static int hf_scsi_asc                   = -1;
static int hf_scsi_ascascq               = -1;
static int hf_scsi_ascq                  = -1;
static int hf_scsi_fru                   = -1;
static int hf_scsi_sksv                  = -1;
static int hf_scsi_inq_normaca           = -1;
static int hf_scsi_persresv_key          = -1;
static int hf_scsi_persresv_scopeaddr    = -1;
static int hf_scsi_add_cdblen = -1;
static int hf_scsi_svcaction = -1;
static int hf_scsi_ssu_immed = -1;
static int hf_scsi_ssu_pwr_cond = -1;
static int hf_scsi_ssu_loej = -1;
static int hf_scsi_ssu_start = -1;
static int hf_scsi_wb_mode = -1;
static int hf_scsi_wb_bufferid = -1;
static int hf_scsi_wb_bufoffset = -1;
static int hf_scsi_paramlen24 = -1;
static int hf_scsi_senddiag_st_code = -1;
static int hf_scsi_senddiag_pf = -1;
static int hf_scsi_senddiag_st = -1;
static int hf_scsi_senddiag_devoff = -1;
static int hf_scsi_senddiag_unitoff = -1;
static int hf_scsi_key_class = -1;
static int hf_scsi_key_format = -1;
static int hf_scsi_agid = -1;
static int hf_scsi_lba             = -1;
static int hf_scsi_read_compatibility_lba             = -1;
static int hf_scsi_num_blocks      = -1;
static int hf_scsi_data_length = -1;
static int hf_scsi_report_key_type_code = -1;
static int hf_scsi_report_key_vendor_resets = -1;
static int hf_scsi_report_key_user_changes = -1;
static int hf_scsi_report_key_region_mask = -1;
static int hf_scsi_report_key_rpc_scheme = -1;
static int hf_scsi_setcdspeed_rc = -1;
static int hf_scsi_getconf_rt = -1;
static int hf_scsi_getconf_starting_feature = -1;
static int hf_scsi_getconf_current_profile = -1;
static int hf_scsi_feature = -1;
static int hf_scsi_feature_version = -1;
static int hf_scsi_feature_persistent = -1;
static int hf_scsi_feature_current = -1;
static int hf_scsi_feature_additional_length = -1;
static int hf_scsi_feature_lun_sn = -1;
static int hf_scsi_feature_cdread_dap = -1;
static int hf_scsi_feature_cdread_c2flag = -1;
static int hf_scsi_feature_cdread_cdtext = -1;
static int hf_scsi_feature_dvdrw_write = -1;
static int hf_scsi_feature_dvdrw_quickstart = -1;
static int hf_scsi_feature_dvdrw_closeonly = -1;
static int hf_scsi_feature_dvdr_write = -1;
static int hf_scsi_feature_tao_buf = -1;
static int hf_scsi_feature_tao_rwraw = -1;
static int hf_scsi_feature_tao_rwpack = -1;
static int hf_scsi_feature_tao_testwrite = -1;
static int hf_scsi_feature_tao_cdrw = -1;
static int hf_scsi_feature_tao_rwsubcode = -1;
static int hf_scsi_feature_dts = -1;
static int hf_scsi_feature_sao_buf = -1;
static int hf_scsi_feature_sao_sao = -1;
static int hf_scsi_feature_sao_rawms = -1;
static int hf_scsi_feature_sao_raw = -1;
static int hf_scsi_feature_sao_testwrite = -1;
static int hf_scsi_feature_sao_cdrw = -1;
static int hf_scsi_feature_sao_rw = -1;
static int hf_scsi_feature_sao_mcsl = -1;
static int hf_scsi_feature_dvdr_buf = -1;
static int hf_scsi_feature_dvdr_testwrite = -1;
static int hf_scsi_feature_dvdr_dvdrw = -1;
static int hf_scsi_feature_profile = -1;
static int hf_scsi_feature_profile_current = -1;
static int hf_scsi_feature_isw_buf = -1;
static int hf_scsi_feature_isw_num_linksize = -1;
static int hf_scsi_feature_isw_linksize = -1;
static int hf_scsi_readtoc_time = -1;
static int hf_scsi_readtoc_format = -1;
static int hf_scsi_track = -1;
static int hf_scsi_track_size = -1;
static int hf_scsi_session = -1;
static int hf_scsi_first_track = -1;
static int hf_scsi_readtoc_first_session = -1;
static int hf_scsi_readtoc_last_track = -1;
static int hf_scsi_readtoc_last_session = -1;
static int hf_scsi_q_subchannel_adr = -1;
static int hf_scsi_q_subchannel_control = -1;
static int hf_scsi_track_start_address = -1;
static int hf_scsi_next_writable_address = -1;
static int hf_scsi_track_start_time = -1;
static int hf_scsi_synccache_immed = -1;
static int hf_scsi_synccache_reladr = -1;
static int hf_scsi_rbc_block = -1;
static int hf_scsi_rbc_lob_blocks = -1;
static int hf_scsi_rbc_alob_blocks = -1;
static int hf_scsi_rbc_lob_bytes = -1;
static int hf_scsi_rbc_alob_bytes = -1;
static int hf_scsi_setstreaming_type = -1;
static int hf_scsi_setstreaming_param_len = -1;
static int hf_scsi_setstreaming_wrc = -1;
static int hf_scsi_setstreaming_rdd = -1;
static int hf_scsi_setstreaming_exact = -1;
static int hf_scsi_setstreaming_ra = -1;
static int hf_scsi_setstreaming_start_lba = -1;
static int hf_scsi_setstreaming_end_lba = -1;
static int hf_scsi_setstreaming_read_size = -1;
static int hf_scsi_setstreaming_read_time = -1;
static int hf_scsi_setstreaming_write_size = -1;
static int hf_scsi_setstreaming_write_time = -1;
static int hf_scsi_reservation_size = -1;
static int hf_scsi_rti_address_type = -1;
static int hf_scsi_rti_damage = -1;
static int hf_scsi_rti_copy = -1;
static int hf_scsi_rti_track_mode = -1;
static int hf_scsi_rti_rt = -1;
static int hf_scsi_rti_blank = -1;
static int hf_scsi_rti_packet = -1;
static int hf_scsi_rti_fp = -1;
static int hf_scsi_rti_data_mode = -1;
static int hf_scsi_rti_lra_v = -1;
static int hf_scsi_rti_nwa_v = -1;
static int hf_scsi_free_blocks = -1;
static int hf_scsi_fixed_packet_size = -1;
static int hf_scsi_last_recorded_address = -1;
static int hf_scsi_disc_info_erasable = -1;
static int hf_scsi_disc_info_state_of_last_session = -1;
static int hf_scsi_disc_info_disk_status = -1;
static int hf_scsi_disc_info_number_of_sessions = -1;
static int hf_scsi_disc_info_first_track_in_last_session = -1;
static int hf_scsi_disc_info_last_track_in_last_session = -1;
static int hf_scsi_disc_info_did_v = -1;
static int hf_scsi_disc_info_dbc_v = -1;
static int hf_scsi_disc_info_uru = -1;
static int hf_scsi_disc_info_dac_v = -1;
static int hf_scsi_disc_info_dbit = -1;
static int hf_scsi_disc_info_bgfs = -1;
static int hf_scsi_disc_info_disc_type = -1;
static int hf_scsi_disc_info_disc_identification = -1;
static int hf_scsi_disc_info_last_session_lead_in_start_address = -1;
static int hf_scsi_disc_info_last_possible_lead_out_start_address = -1;
static int hf_scsi_disc_info_disc_bar_code = -1;
static int hf_sbc2_verify_lba = -1;
static int hf_sbc2_verify_vlen = -1;
static int hf_sbc2_verify_dpo = -1;
static int hf_sbc2_verify_blkvfy = -1;
static int hf_sbc2_verify_reladdr = -1;
static int hf_sbc2_verify_vlen32 = -1;
static int hf_sbc2_verify_lba64 = -1;
static int hf_sbc2_wrverify_ebp = -1;
static int hf_sbc2_wrverify_lba = -1;
static int hf_sbc2_wrverify_xferlen = -1;
static int hf_sbc2_wrverify_lba64 = -1;
static int hf_sbc2_wrverify_xferlen32 = -1;
static int hf_sbc2_verify_bytchk = -1;
static int hf_ssc3_space6_count = -1;
static int hf_ssc3_space16_count = -1;
static int hf_ssc3_locate10_loid = -1;
static int hf_ssc3_locate16_loid = -1;

static gint ett_scsi         = -1;
static gint ett_scsi_page    = -1;
static gint ett_scsi_profile = -1;


/* These two defines are used to handle cases where data coming back from
 * the device is truncated due to a too short allocation_length specified
 * in the command CDB.
 * This is semi-common in SCSI and it would be wrong to mark these packets
 * as [malformed packets].
 * These macros will reset the reported length to what the data pdu specified
 * and if a BoundsError is generated we will instead throw ScsiBoundsError
 *
 * Please see dissect_mmc4_getconfiguration() for an example how to use these
 * macros.
 */
#define TRY_SCSI_SHORT_TRANSFER(pinfo, tvb, offset, length)		\
    {									\
	gboolean short_packet;						\
	tvbuff_t *new_tvb;						\
									\
	short_packet=pinfo->fd->cap_len<pinfo->fd->pkt_len;		\
	new_tvb=tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);\
	tvb=new_tvb;							\
	offset=0;							\
	TRY {

#define END_TRY_SCSI_SHORT_TRANSFER 					\
	    } /* TRY */							\
	CATCH(BoundsError) {						\
		if(short_packet){					\
			/* this was a short packet */			\
			RETHROW;					\
		} else {						\
			/* this packet was not really short but limited	\
			 * due to a short SCSI allocation length	\
			 */						\
			THROW(ScsiBoundsError);				\
		}							\
	    }								\
	CATCH_ALL {							\
		RETHROW;						\
	}								\
	ENDTRY;								\
    }


typedef guint32 scsi_cmnd_type;
typedef guint32 scsi_device_type;

/* Valid SCSI Command Types */
#define SCSI_CMND_SPC2                   1
#define SCSI_CMND_SBC2                   2
#define SCSI_CMND_SSC2                   3
#define SCSI_CMND_SMC2                   4
#define SCSI_CMND_MMC                    5

/* SPC and SPC-2 Commands */

#define SCSI_SPC_CHANGE_DEFINITION       0x40
#define SCSI_SPC_COMPARE                 0x39
#define SCSI_SPC_COPY                    0x18
#define SCSI_SPC_COPY_AND_VERIFY         0x3A
#define SCSI_SPC2_INQUIRY                0x12
#define SCSI_SPC2_EXTCOPY                0x83
#define SCSI_SPC2_LOGSELECT              0x4C
#define SCSI_SPC2_LOGSENSE               0x4D
#define SCSI_SPC2_MODESELECT6            0x15
#define SCSI_SPC2_MODESELECT10           0x55
#define SCSI_SPC2_MODESENSE6             0x1A
#define SCSI_SPC2_MODESENSE10            0x5A
#define SCSI_SPC2_PERSRESVIN             0x5E
#define SCSI_SPC2_PERSRESVOUT            0x5F
#define SCSI_SPC2_PREVMEDREMOVAL         0x1E
#define SCSI_SPC2_READBUFFER             0x3C
#define SCSI_SPC2_RCVCOPYRESULTS         0x84
#define SCSI_SPC2_RCVDIAGRESULTS         0x1C
#define SCSI_SPC2_RELEASE6               0x17
#define SCSI_SPC2_RELEASE10              0x57
#define SCSI_SPC2_REPORTDEVICEID         0xA3
#define SCSI_SPC2_REPORTLUNS             0xA0
#define SCSI_SPC2_REQSENSE               0x03
#define SCSI_SPC2_RESERVE6               0x16
#define SCSI_SPC2_RESERVE10              0x56
#define SCSI_SPC2_SENDDIAG               0x1D
#define SCSI_SPC2_SETDEVICEID            0xA4
#define SCSI_SPC2_TESTUNITRDY            0x00
#define SCSI_SPC2_WRITEBUFFER            0x3B
#define SCSI_SPC2_VARLENCDB              0x7F

static const value_string scsi_spc2_val[] = {
    {SCSI_SPC_CHANGE_DEFINITION  , "Change Definition"},
    {SCSI_SPC_COMPARE            , "Compare"},
    {SCSI_SPC_COPY               , "Copy"},
    {SCSI_SPC_COPY_AND_VERIFY    , "Copy And Verify"},
    {SCSI_SPC2_EXTCOPY           , "Extended Copy"},
    {SCSI_SPC2_INQUIRY           , "Inquiry"},
    {SCSI_SPC2_LOGSELECT         , "Log Select"},
    {SCSI_SPC2_LOGSENSE          , "Log Sense"},
    {SCSI_SPC2_MODESELECT6       , "Mode Select(6)"},
    {SCSI_SPC2_MODESELECT10      , "Mode Select(10)"},
    {SCSI_SPC2_MODESENSE6        , "Mode Sense(6)"},
    {SCSI_SPC2_MODESENSE10       , "Mode Sense(10)"},
    {SCSI_SPC2_PERSRESVIN        , "Persistent Reserve In"},
    {SCSI_SPC2_PERSRESVOUT       , "Persistent Reserve Out"},
    {SCSI_SPC2_PREVMEDREMOVAL    , "Prevent/Allow Medium Removal"},
    {SCSI_SPC2_RCVCOPYRESULTS    , "Receive Copy Results"},
    {SCSI_SPC2_RCVDIAGRESULTS    , "Receive Diagnostics Results"},
    {SCSI_SPC2_READBUFFER        , "Read Buffer"},
    {SCSI_SPC2_RELEASE6          , "Release(6)"},
    {SCSI_SPC2_RELEASE10         , "Release(10)"},
    {SCSI_SPC2_REPORTDEVICEID    , "Report Device ID"},
    {SCSI_SPC2_REPORTLUNS        , "Report LUNs"},
    {SCSI_SPC2_REQSENSE          , "Request Sense"},
    {SCSI_SPC2_RESERVE6          , "Reserve(6)"},
    {SCSI_SPC2_RESERVE10         , "Reserve(10)"},
    {SCSI_SPC2_SENDDIAG          , "Send Diagnostic"},
    {SCSI_SPC2_TESTUNITRDY       , "Test Unit Ready"},
    {SCSI_SPC2_WRITEBUFFER       , "Write Buffer"},
    {SCSI_SPC2_VARLENCDB         , "Variable Length CDB"},
    {0, NULL},
};

/* SBC-2 Commands */
#define SCSI_SBC2_FORMATUNIT             0x04
#define SCSI_SBC2_LOCKUNLKCACHE10        0x36
#define SCSI_SBC2_LOCKUNLKCACHE16        0x92
#define SCSI_SBC2_PREFETCH10             0x34
#define SCSI_SBC2_PREFETCH16             0x90
#define SCSI_SBC2_READ6                  0x08
#define SCSI_SBC2_READ10                 0x28
#define SCSI_SBC2_READ12                 0xA8
#define SCSI_SBC2_READ16                 0x88
#define SCSI_SBC2_READCAPACITY10         0x25
#define SCSI_SBC2_SERVICEACTIONIN16      0x9E
#define SCSI_SBC2_READDEFDATA10          0x37
#define SCSI_SBC2_READDEFDATA12          0xB7
#define SCSI_SBC2_READLONG               0x3E
#define SCSI_SBC2_REASSIGNBLKS           0x07
#define SCSI_SBC2_REBUILD16              0x81
#define SCSI_SBC2_REBUILD32              0x7F
#define SCSI_SBC2_REGENERATE16           0x82
#define SCSI_SBC2_REGENERATE32           0x7F
#define SCSI_SBC2_SEEK10                 0x2B
#define SCSI_SBC2_SETLIMITS10            0x33
#define SCSI_SBC2_SETLIMITS12            0xB3
#define SCSI_SBC2_STARTSTOPUNIT          0x1B
#define SCSI_SBC2_SYNCCACHE10            0x35
#define SCSI_SBC2_SYNCCACHE16            0x91
#define SCSI_SBC2_VERIFY10               0x2F
#define SCSI_SBC2_VERIFY12               0xAF
#define SCSI_SBC2_VERIFY16               0x8F
#define SCSI_SBC2_WRITE6                 0x0A
#define SCSI_SBC2_WRITE10                0x2A
#define SCSI_SBC2_WRITE12                0xAA
#define SCSI_SBC2_WRITE16                0x8A
#define SCSI_SBC2_WRITENVERIFY10         0x2E
#define SCSI_SBC2_WRITENVERIFY12         0xAE
#define SCSI_SBC2_WRITENVERIFY16         0x8E
#define SCSI_SBC2_WRITELONG              0x3F
#define SCSI_SBC2_WRITESAME10            0x41
#define SCSI_SBC2_WRITESAME16            0x93
#define SCSI_SBC2_XDREAD10               0x52
#define SCSI_SBC2_XDREAD32               0x7F
#define SCSI_SBC2_XDWRITE10              0x50
#define SCSI_SBC2_XDWRITE32              0x7F
#define SCSI_SBC2_XDWRITEREAD10          0x53
#define SCSI_SBC2_XDWRITEREAD32          0x7F
#define SCSI_SBC2_XDWRITEEXTD16          0x80
#define SCSI_SBC2_XDWRITEEXTD32          0x7F
#define SCSI_SBC2_XPWRITE10              0x51
#define SCSI_SBC2_XPWRITE32              0x7F


static const value_string scsi_sbc2_val[] = {
    {SCSI_SBC2_FORMATUNIT    , "Format Unit"},
    {SCSI_SBC2_LOCKUNLKCACHE10, "Lock Unlock Cache(10)"},
    {SCSI_SBC2_LOCKUNLKCACHE16, "Lock Unlock Cache(16)"},
    {SCSI_SBC2_PREFETCH10, "Pre-Fetch(10)"},
    {SCSI_SBC2_PREFETCH16, "Pre-Fetch(16)"},
    {SCSI_SBC2_READ6         , "Read(6)"},
    {SCSI_SBC2_READ10        , "Read(10)"},
    {SCSI_SBC2_READ12        , "Read(12)"},
    {SCSI_SBC2_READ16        , "Read(16)"},
    {SCSI_SBC2_READCAPACITY10, "Read Capacity(10)"},
    {SCSI_SBC2_SERVICEACTIONIN16, "Service Action In(16)"},
    {SCSI_SBC2_READDEFDATA10 , "Read Defect Data(10)"},
    {SCSI_SBC2_READDEFDATA12 , "Read Defect Data(12)"},
    {SCSI_SBC2_READLONG, "Read Long"},
    {SCSI_SBC2_REASSIGNBLKS  , "Reassign Blocks"},
    {SCSI_SBC2_REBUILD16, "Rebuild(16)"},
    {SCSI_SBC2_REBUILD32, "Rebuild(32)"},
    {SCSI_SBC2_REGENERATE16, "Regenerate(16)"},
    {SCSI_SBC2_REGENERATE32, "Regenerate(32)"},
    {SCSI_SBC2_SEEK10, "Seek(10)"},
    {SCSI_SBC2_SETLIMITS10, "Set Limits(10)"},
    {SCSI_SBC2_SETLIMITS12, "Set Limits(12)"},
    {SCSI_SBC2_STARTSTOPUNIT, "Start Stop Unit"},
    {SCSI_SBC2_SYNCCACHE10, "Synchronize Cache(10)"},
    {SCSI_SBC2_SYNCCACHE16, "Synchronize Cache(16)"},
    {SCSI_SBC2_VERIFY10, "Verify(10)"},
    {SCSI_SBC2_VERIFY12, "Verify(12)"},
    {SCSI_SBC2_VERIFY16, "Verify(16)"},
    {SCSI_SBC2_WRITE6        , "Write(6)"},
    {SCSI_SBC2_WRITE10       , "Write(10)"},
    {SCSI_SBC2_WRITE12       , "Write(12)"},
    {SCSI_SBC2_WRITE16       , "Write(16)"},
    {SCSI_SBC2_WRITENVERIFY10, "Write & Verify(10)"},
    {SCSI_SBC2_WRITENVERIFY12, "Write & Verify(12)"},
    {SCSI_SBC2_WRITENVERIFY16, "Write & Verify(16)"},
    {SCSI_SBC2_WRITELONG, "Write Long"},
    {SCSI_SBC2_WRITESAME10, "Write Same(10)"},
    {SCSI_SBC2_WRITESAME16, "Write Same(16)"},
    {SCSI_SBC2_XDREAD10, "XdRead(10)"},
    {SCSI_SBC2_XDREAD32, "XdRead(32)"},
    {SCSI_SBC2_XDWRITE10, "XdWrite(10)"},
    {SCSI_SBC2_XDWRITE32, "XdWrite(32)"},
    {SCSI_SBC2_XDWRITEREAD10, "XdWriteRead(10)"},
    {SCSI_SBC2_XDWRITEREAD32, "XdWriteRead(32)"},
    {SCSI_SBC2_XDWRITEEXTD16, "XdWrite Extended(16)"},
    {SCSI_SBC2_XDWRITEEXTD32, "XdWrite Extended(32)"},
    {SCSI_SBC2_XPWRITE10, "XpWrite(10)"},
    {SCSI_SBC2_XPWRITE32, "XpWrite(32)"},
    {0, NULL},
};

/* MMC Commands */
#define SCSI_MMC_READCAPACITY10         0x25
#define SCSI_MMC_READ10                 0x28
#define SCSI_MMC_WRITE10                0x2a
#define SCSI_MMC_SYNCHRONIZECACHE       0x35
#define SCSI_MMC_READTOCPMAATIP         0x43
#define SCSI_MMC_GETCONFIGURATION       0x46
#define SCSI_MMC_GETEVENTSTATUSNOTIFY   0x4a
#define SCSI_MMC_READDISCINFORMATION    0x51
#define SCSI_MMC_READTRACKINFORMATION   0x52
#define SCSI_MMC_RESERVETRACK           0x53
#define SCSI_MMC_READBUFFERCAPACITY     0x5c
#define SCSI_MMC_REPORTKEY		0xa4
#define SCSI_MMC_READ12                 0xa8
#define SCSI_MMC_WRITE12                0xaa
#define SCSI_MMC_GETPERFORMANCE         0xac
#define SCSI_MMC_READDISCSTRUCTURE      0xad
#define SCSI_MMC_SETSTREAMING           0xb6
#define SCSI_MMC_SETCDSPEED             0xbb
static const value_string scsi_mmc_val[] = {
    {SCSI_SBC2_STARTSTOPUNIT, "Start Stop Unit"},
    {SCSI_MMC_READCAPACITY10,	"Read Capacity(10)"},
    {SCSI_MMC_READ10,		"Read(10)"},
    {SCSI_MMC_WRITE10,		"Write(10)"},
    {SCSI_MMC_SYNCHRONIZECACHE,	"Synchronize Cache"},
    {SCSI_MMC_READTOCPMAATIP,	"Read TOC/PMA/ATIP"},
    {SCSI_MMC_GETCONFIGURATION,	"Get Configuraion"},
    {SCSI_MMC_GETEVENTSTATUSNOTIFY, "Get Event Status Notification"},
    {SCSI_MMC_READDISCINFORMATION, "Read Disc Information"},
    {SCSI_MMC_READTRACKINFORMATION, "Read Track Information"},
    {SCSI_MMC_RESERVETRACK,	"Reserve Track"},
    {SCSI_MMC_READBUFFERCAPACITY,"Read Buffer Capacity"},
    {SCSI_MMC_REPORTKEY,	"Report Key"},
    {SCSI_MMC_READ12,		"Read(12)"},
    {SCSI_MMC_WRITE12,		"Write(12)"},
    {SCSI_MMC_GETPERFORMANCE,   "Get Performance"},
    {SCSI_MMC_READDISCSTRUCTURE, "Read DISC Structure"},
    {SCSI_MMC_SETSTREAMING,	"Set Streaming"},
    {SCSI_MMC_SETCDSPEED,       "Set CD Speed"},
    {0, NULL},
};

/* SMC2 Commands */
#define SCSI_SMC2_EXCHANGE_MEDIUM                 0x40
#define SCSI_SMC2_INITIALIZE_ELEMENT_STATUS       0x07
#define SCSI_SMC2_INITIALIZE_ELEMENT_STATUS_RANGE 0x37
#define SCSI_SMC2_MOVE_MEDIUM                     0xA5
#define SCSI_SMC2_MOVE_MEDIUM_ATTACHED            0xA7
#define SCSI_SMC2_POSITION_TO_ELEMENT             0x2B
#define SCSI_SMC2_READ_ATTRIBUTE                  0x8C
#define SCSI_SMC2_READ_ELEMENT_STATUS             0xB8
#define SCSI_SMC2_READ_ELEMENT_STATUS_ATTACHED    0xB4
#define SCSI_SMC2_REQUEST_VOLUME_ELEMENT_ADDRESS  0xB5
#define SCSI_SMC2_SEND_VOLUME_TAG                 0xB6
#define SCSI_SMC2_WRITE_ATTRIBUTE                 0x8D

static const value_string scsi_smc2_val[] = {
    {SCSI_SMC2_EXCHANGE_MEDIUM                , "Exchange Medium"},
    {SCSI_SMC2_INITIALIZE_ELEMENT_STATUS      , "Initialize Element Status"},
    {SCSI_SMC2_INITIALIZE_ELEMENT_STATUS_RANGE, "Initialize Element Status With Range"},
    {SCSI_SMC2_MOVE_MEDIUM                    , "Move Medium"},
    {SCSI_SMC2_MOVE_MEDIUM_ATTACHED           , "Move Medium Attached"},
    {SCSI_SMC2_POSITION_TO_ELEMENT            , "Position To Element"},
    {SCSI_SMC2_READ_ATTRIBUTE                 , "Read Attribute"},
    {SCSI_SMC2_READ_ELEMENT_STATUS            , "Read Element Status"},
    {SCSI_SMC2_READ_ELEMENT_STATUS_ATTACHED   , "Read Element Status Attached"},
    {SCSI_SMC2_REQUEST_VOLUME_ELEMENT_ADDRESS , "Request Volume Element Address"},
    {SCSI_SMC2_SEND_VOLUME_TAG                , "Send Volume Tag"},
    {SCSI_SMC2_WRITE_ATTRIBUTE                , "Write Attribute"},
    {0, NULL},
};


/* SSC2 Commands */
#define SCSI_SSC2_REWIND                        0x01
#define SCSI_SSC2_FORMAT_MEDIUM                 0x04
#define SCSI_SSC2_READ_BLOCK_LIMITS             0x05
#define SCSI_SSC2_READ6                         0x08
#define SCSI_SSC2_WRITE6                        0x0A
#define SCSI_SSC2_SET_CAPACITY                  0x0B
#define SCSI_SSC2_READ_REVERSE_6                0x0F
#define SCSI_SSC2_WRITE_FILEMARKS_6             0x10
#define SCSI_SSC2_SPACE_6                       0x11
#define SCSI_SSC2_VERIFY_6                      0x13
#define SCSI_SSC2_RECOVER_BUFFERED_DATA         0x14
#define SCSI_SSC2_ERASE_6                       0x19
#define SCSI_SSC2_LOAD_UNLOAD                   0x1B
#define SCSI_SSC2_LOCATE_10                     0x2B
#define SCSI_SSC2_READ_POSITION                 0x34
#define SCSI_SSC2_REPORT_DENSITY_SUPPORT        0x44
#define SCSI_SSC2_WRITE_FILEMARKS_16            0x80
#define SCSI_SSC2_READ_REVERSE_16               0x81
#define SCSI_SSC2_READ_16                       0x88
#define SCSI_SSC2_WRITE_16                      0x8A
#define SCSI_SSC2_VERIFY_16                     0x8F
#define SCSI_SSC2_SPACE_16                      0x91
#define SCSI_SSC2_LOCATE_16                     0x92
#define SCSI_SSC2_ERASE_16                      0x93

/* For commands from SPC we have automatic fallback, for all
 * commands not in SSC and not from SPC we must add them to this
 * value string for proper prettyprinting.
 */
static const value_string scsi_ssc2_val[] = {
    {SCSI_SSC2_ERASE_16                    , "Erase(16)"},
    {SCSI_SSC2_FORMAT_MEDIUM               , "Format Medium"},
    {SCSI_SSC2_LOAD_UNLOAD                 , "Load Unload"},
    {SCSI_SSC2_LOCATE_16                   , "Locate(16)"},
    {SCSI_SSC2_READ_16                     , "Read(16)"},
    {SCSI_SSC2_READ_BLOCK_LIMITS           , "Read Block Limits"},
    {SCSI_SSC2_READ_POSITION               , "Read Position"},
    {SCSI_SSC2_READ_REVERSE_16             , "Read Reverse(16)"},
    {SCSI_SSC2_RECOVER_BUFFERED_DATA       , "Recover Buffered Data"},
    {SCSI_SSC2_REPORT_DENSITY_SUPPORT      , "Report Density Support"},
    {SCSI_SSC2_REWIND                      , "Rewind"},
    {SCSI_SSC2_SET_CAPACITY                , "Set Capacity"},
    {SCSI_SSC2_SPACE_16                    , "Space(16)"},
    {SCSI_SSC2_VERIFY_16                   , "Verify(16)"},
    {SCSI_SSC2_WRITE_16                    , "Write(16)"},
    {SCSI_SSC2_WRITE_FILEMARKS_16          , "Write Filemarks(16)"},
    {SCSI_SSC2_ERASE_6                     , "Erase(6)"},
    {SCSI_SSC2_LOCATE_10                   , "Locate(10)"},
    {SCSI_SSC2_LOCATE_16                   , "Locate(16)"},
    {SCSI_SSC2_READ6                       , "Read(6)"},
    {SCSI_SSC2_READ_REVERSE_6              , "Read Reverse(6)"},
    {SCSI_SSC2_SPACE_6                     , "Space(6)"},
    {SCSI_SSC2_VERIFY_6                    , "Verify(6)"},
    {SCSI_SSC2_WRITE6                      , "Write(6)"},
    {SCSI_SSC2_WRITE_FILEMARKS_6           , "Write Filemarks(6)"},
    {SCSI_SMC2_MOVE_MEDIUM                 , "Move Medium"},
    {SCSI_SMC2_MOVE_MEDIUM_ATTACHED        , "Move Medium Attached"},
    {SCSI_SMC2_READ_ELEMENT_STATUS         , "Read Element Status"},
    {SCSI_SMC2_READ_ELEMENT_STATUS_ATTACHED, "Read Element Status Attached"},
    {0, NULL},
};

static const value_string scsi_select_report_val[] = {
    {0,	"Select All LUNs" },
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
    {0, NULL},
};

static const value_string scsi_logsel_pc_val[] = {
    {0, "Current Threshold Values"},
    {1, "Current Cumulative Values"},
    {2, "Default Threshold Values"},
    {3, "Default Cumulative Values"},
    {0, NULL},
};

static const value_string scsi_logsns_pc_val[] = {
    {0, "Threshold Values"},
    {1, "Cumulative Values"},
    {2, "Default Threshold Values"},
    {3, "Default Cumulative Values"},
    {0, NULL},
};

static const value_string scsi_logsns_page_val[] = {
    {0xF, "Application Client Page"},
    {0x1, "Buffer Overrun/Underrun Page"},
    {0x3, "Error Counter (read) Page"},
    {0x4, "Error Counter (read reverse) Page"},
    {0x5, "Error Counter (verify) Page"},
    {0x1, "Error Counter (write) Page"},
    {0xB, "Last n Deferred Errors or Async Events Page"},
    {0x7, "Last n Error Events Page"},
    {0x6, "Non-medium Error Page"},
    {0x10, "Self-test Results Page"},
    {0xE, "Start-Stop Cycle Counter Page"},
    {0x0, "Supported Log Pages"},
    {0xD, "Temperature Page"},
    {0, NULL},
};

static const value_string scsi_modesns_pc_val[] = {
    {0, "Current Values"},
    {1, "Changeable Values"},
    {2, "Default Values"},
    {3, "Saved Values"},
    {0, NULL},
};

#define SCSI_SPC2_MODEPAGE_CTL      0x0A
#define SCSI_SPC2_MODEPAGE_DISCON   0x02
#define SCSI_SCSI2_MODEPAGE_PERDEV  0x09  /* Obsolete in SPC-2; generic in SCSI-2 */
#define SCSI_SPC2_MODEPAGE_INFOEXCP 0x1C
#define SCSI_SPC2_MODEPAGE_PWR      0x1A
#define SCSI_SPC2_MODEPAGE_LUN      0x18
#define SCSI_SPC2_MODEPAGE_PORT     0x19
#define SCSI_SPC2_MODEPAGE_VEND     0x00

static const value_string scsi_spc2_modepage_val[] = {
    {SCSI_SPC2_MODEPAGE_CTL,      "Control"},
    {SCSI_SPC2_MODEPAGE_DISCON,   "Disconnect-Reconnect"},
    {SCSI_SCSI2_MODEPAGE_PERDEV,  "Peripheral Device"},
    {SCSI_SPC2_MODEPAGE_INFOEXCP, "Informational Exceptions Control"},
    {SCSI_SPC2_MODEPAGE_PWR,      "Power Condition"},
    {SCSI_SPC2_MODEPAGE_LUN,      "Protocol Specific LUN"},
    {SCSI_SPC2_MODEPAGE_PORT,     "Protocol-Specific Port"},
    {SCSI_SPC2_MODEPAGE_VEND,     "Vendor Specific Page"},
    {0x3F,                        "Return All Mode Pages"},
    {0, NULL},
};

#define SCSI_SBC2_MODEPAGE_RDWRERR  0x01
#define SCSI_SBC2_MODEPAGE_FMTDEV   0x03
#define SCSI_SBC2_MODEPAGE_DISKGEOM 0x04
#define SCSI_SBC2_MODEPAGE_FLEXDISK 0x05
#define SCSI_SBC2_MODEPAGE_VERERR   0x07
#define SCSI_SBC2_MODEPAGE_CACHE    0x08
#define SCSI_SBC2_MODEPAGE_MEDTYPE  0x0B
#define SCSI_SBC2_MODEPAGE_NOTPART  0x0C
#define SCSI_SBC2_MODEPAGE_XORCTL   0x10

static const value_string scsi_sbc2_modepage_val[] = {
    {SCSI_SBC2_MODEPAGE_RDWRERR,  "Read/Write Error Recovery"},
    {SCSI_SBC2_MODEPAGE_FMTDEV,   "Format Device"},
    {SCSI_SBC2_MODEPAGE_DISKGEOM, "Rigid Disk Geometry"},
    {SCSI_SBC2_MODEPAGE_FLEXDISK, "Flexible Disk"},
    {SCSI_SBC2_MODEPAGE_VERERR,   "Verify Error Recovery"},
    {SCSI_SBC2_MODEPAGE_CACHE,    "Caching"},
    {SCSI_SBC2_MODEPAGE_MEDTYPE,  "Medium Types Supported"},
    {SCSI_SBC2_MODEPAGE_NOTPART,  "Notch & Partition"},
    {SCSI_SBC2_MODEPAGE_XORCTL,   "XOR Control"},
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

#define SCSI_SMC2_MODEPAGE_EAA      0x1D  /* element address assignment */
#define SCSI_SMC2_MODEPAGE_TRANGEOM 0x1E  /* transport geometry parameters */
#define SCSI_SMC2_MODEPAGE_DEVCAP   0x1F  /* device capabilities */

static const value_string scsi_smc2_modepage_val[] = {
    {SCSI_SMC2_MODEPAGE_EAA,      "Element Address Assignment"},
    {SCSI_SMC2_MODEPAGE_TRANGEOM, "Transport Geometry Parameters"},
    {SCSI_SMC2_MODEPAGE_DEVCAP,   "Device Capabilities"},
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

#define SCSI_SPC2_RESVIN_SVCA_RDKEYS 0
#define SCSI_SPC2_RESVIN_SVCA_RDRESV 1

static const value_string scsi_persresvin_svcaction_val[] = {
    {SCSI_SPC2_RESVIN_SVCA_RDKEYS, "Read Keys"},
    {SCSI_SPC2_RESVIN_SVCA_RDRESV, "Read Reservation"},
    {0, NULL},
};

static const value_string scsi_persresvout_svcaction_val[] = {
    {0, "Register"},
    {1, "Reserve"},
    {2, "Release"},
    {3, "Clear"},
    {4, "Preempt"},
    {5, "Preempt & Abort"},
    {6, "Register & Ignore Existing Key"},
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
    {7, "Excl Access, Registrants Only"},
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
    {"block", "Block Device", SCSI_DEV_SBC},
    {"sequential", "Sequential Device", SCSI_DEV_SSC},
    {NULL, NULL, -1},
};

static const value_string scsi_inquiry_vers_val[] = {
    {0, "No Compliance to any Standard"},
    {2, "Compliance to ANSI X3.131:1994"},
    {3, "Compliance to ANSI X3.301:1997"},
    {4, "Compliance to SPC-2"},
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
    {0x0d40, "FC-AL (No Version)"},
    {0x0d5c, "FC-AL ANSI X3.272:1996"},
    {0x0d60, "FC-AL-2 (no version claimed)"},
    {0x0d7c, "FC-AL-2 ANSI NCITS.332:1999"},
    {0x0d61, "FC-AL-2 T11/1133 revision 7.0"},
    {0x1320, "FC-FLA (no version claimed)"},
    {0x133c, "FC-FLA ANSI NCITS TR-20:1998"},
    {0x133b, "FC-FLA T11/1235 revision 7"},
    {0x0da0, "FC-FS (no version claimed)"},
    {0x0db7, "FC-FS T11/1331 revision 1.2"},
    {0x08c0, "FCP (no version claimed)"},
    {0x08dc, "FCP ANSI X3.269:1996"},
    {0x08db, "FCP T10/0993 revision 12"},
    {0x1340, "FC-PLDA (no version claimed)"},
    {0x135c, "FC-PLDA ANSI NCITS TR-19:1998"},
    {0x135b, "FC-PLDA T11/1162 revision 2.1"},
    {0x0900, "FCP-2 (no version claimed)"},
    {0x0901, "FCP-2 T10/1144 revision 4"},
    {0x003c, "SAM ANSI X3.270:1996"},
    {0x003b, "SAM T10/0994 revision 18"},
    {0x0040, "SAM-2 (no version claimed)"},
    {0x0020, "SAM (no version claimed)"},
    {0x0180, "SBC (no version claimed)"},
    {0x019c, "SBC ANSI NCITS.306:1998"},
    {0x019b, "SBC T10/0996 revision 08c"},
    {0x0320, "SBC-2 (no version claimed)"},
    {0x01c0, "SES (no version claimed)"},
    {0x01dc, "SES ANSI NCITS.305:1998"},
    {0x01db, "SES T10/1212 revision 08b"},
    {0x01de, "SES ANSI NCITS.305:1998 w/ Amendment ANSI NCITS.305/AM1:2000"},
    {0x01dd, "SES T10/1212 revision 08b w/ Amendment ANSI NCITS.305/AM1:2000"},
    {0x0120, "SPC (no version claimed)"},
    {0x013c, "SPC ANSI X3.301:1997"},
    {0x013b, "SPC T10/0995 revision 11a"},
    {0x0260, "SPC-2 (no version claimed)"},
    {0x0267, "SPC-2 T10/1236 revision 12"},
    {0x0269, "SPC-2 T10/1236 revision 18"},
    {0x0300, "SPC-3 (no version claimed)"},
    {0x0960, "iSCSI (no version claimed)"},
    {0x0d80, "FC-PH-3 (no version claimed)"},
    {0x0d9c, "FC-PH-3 ANSI X3.303-1998"},
    {0x0d20, "FC-PH (no version claimed)"},
    {0, NULL},
};

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

#define CODESET_BINARY	1
#define CODESET_ASCII	2

static const value_string scsi_devid_codeset_val[] = {
    {0,              "Reserved"},
    {CODESET_BINARY, "Identifier field contains binary values"},
    {CODESET_ASCII,  "Identifier field contains ASCII graphic codes"},
    {0,              NULL},
};

static const value_string scsi_devid_assoc_val[] = {
    {0, "Identifier is associated with addressed logical/physical device"},
    {1, "Identifier is associated with the port that received the request"},
    {0, NULL},
};

static const value_string scsi_devid_idtype_val[] = {
    {0, "Vendor-specific ID (non-globally unique)"},
    {1, "Vendor-ID + vendor-specific ID (globally unique)"},
    {2, "EUI-64 ID"},
    {3, "WWN"},
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

static const value_string scsi_sns_errtype_val[] = {
    {0x70, "Current Error"},
    {0x71, "Deferred Error"},
    {0x72, "Current Error"},
    {0x73, "Deferred Error"},
    {0x7F, "Vendor Specific"},
    {0, NULL},
};

static const value_string scsi_asc_val[] = {
    {0x0000,  "No Additional Sense Information"},
    {0x0006,  "I/O Process Terminated"},
    {0x0016,  "Operation In Progress"},
    {0x0017,  "Cleaning Requested"},
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

const value_string scsi_ssu_pwrcnd_val[] = {
    {0x0, "No Change"},
    {0x1, "Place Device In Active Condition"},
    {0x2, "Place device into Idle condition"},
    {0x3, "Place device into Standby condition"},
    {0x4, "Reserved"},
    {0x5, "Place device into Sleep condition"},
    {0x6, "Reserved"},
    {0x7, "Transfer control of power conditions to block device"},
    {0x8, "Reserved"},
    {0x9, "Reserved"},
    {0xA, "Force Idle Condition Timer to zero"},
    {0xB, "Force Standby Condition Timer to zero"},
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
    "Vendor-specific Page Format",
    "Standard Page Format",
};

static gint scsi_def_devtype = SCSI_DEV_SBC;

/*
 * We track SCSI requests and responses with a hash table.
 * The key is a "scsi_task_id_t" structure; the data is a
 * "scsi_task_data_t" structure.
 *
 * We remember:
 *
 *    the command code and type of command (it's not present in the
 *        response, and we need it to dissect the response);
 *    the type of device it's on;
 *
 * and we also have a field to record flags in case the interpretation
 * of the response data depends on data from the command.
 */
typedef struct _scsi_task_data {
    guint32 opcode;
    scsi_cmnd_type cmd;
    scsi_device_type devtype;
    guint16 flags;
    struct _scsi_cdb_table_t *cdb_table;
    const value_string *cdb_vals;
} scsi_task_data_t;

/*
 * The next two data structures are used to track SCSI device type.
 *
 * XXX - it might not be sufficient to use the address of the server
 * to which SCSI CDBs are being sent to identify the device, as
 *
 *	1) a server might have multiple targets or logical units;
 *
 *	2) a server might make a different logical unit refer to
 *	   different devices for different clients;
 *
 * so we should really base this on the connection index for the
 * connection and on a device identifier supplied to us by our caller,
 * not on a network-layer address.
 */
typedef struct _scsi_devtype_key {
    address devid;
} scsi_devtype_key_t;

typedef struct _scsi_devtype_data {
    scsi_device_type devtype;
} scsi_devtype_data_t;

static GHashTable *scsi_req_hash = NULL;

static GHashTable *scsidev_req_hash = NULL;

static dissector_handle_t data_handle;

/*
 * Hash Functions
 */
static gint
scsi_equal(gconstpointer v, gconstpointer w)
{
  const scsi_task_id_t *v1 = (const scsi_task_id_t *)v;
  const scsi_task_id_t *v2 = (const scsi_task_id_t *)w;

  return (v1->conv_id == v2->conv_id && v1->task_id == v2->task_id);
}

static guint
scsi_hash (gconstpointer v)
{
	const scsi_task_id_t *key = (const scsi_task_id_t *)v;
	guint val;

	val = key->conv_id + key->task_id;

	return val;
}

static gint
scsidev_equal (gconstpointer v, gconstpointer w)
{
    const scsi_devtype_key_t *k1 = (const scsi_devtype_key_t *)v;
    const scsi_devtype_key_t *k2 = (const scsi_devtype_key_t *)w;

    if (ADDRESSES_EQUAL (&k1->devid, &k2->devid))
        return 1;
    else
        return 0;
}

static guint
scsidev_hash (gconstpointer v)
{
    const scsi_devtype_key_t *key = (const scsi_devtype_key_t *)v;
    guint val;
    int i;

    val = 0;
    for (i = 0; i < key->devid.len; i++)
        val += key->devid.data[i];
    val += key->devid.type;

    return val;
}

static scsi_task_data_t *
scsi_new_task (packet_info *pinfo)
{
    scsi_task_data_t *cdata = NULL;
    scsi_task_id_t ckey, *req_key;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey = *(scsi_task_id_t *)pinfo->private_data;

        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
        if (!cdata) {
            req_key = se_alloc (sizeof(scsi_task_id_t));
            *req_key = *(scsi_task_id_t *)pinfo->private_data;

            cdata = se_alloc (sizeof(scsi_task_data_t));

            g_hash_table_insert (scsi_req_hash, req_key, cdata);
        }
    }
    return (cdata);
}

static scsi_task_data_t *
scsi_find_task (packet_info *pinfo)
{
    scsi_task_data_t *cdata = NULL;
    scsi_task_id_t ckey;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey = *(scsi_task_id_t *)pinfo->private_data;

        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
    }
    return (cdata);
}

static void
scsi_end_task (packet_info *pinfo)
{
    scsi_task_data_t *cdata = NULL;
    scsi_task_id_t ckey;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey = *(scsi_task_id_t *)pinfo->private_data;
        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
        if (cdata) {
            g_hash_table_remove (scsi_req_hash, &ckey);
        }
    }
}

/*
 * Protocol initialization
 */
static void
free_devtype_key_dev_info(gpointer key_arg, gpointer value_arg _U_,
    gpointer user_data _U_)
{
	scsi_devtype_key_t *key = key_arg;

	if (key->devid.data != NULL) {
		g_free((gpointer)key->devid.data);
		key->devid.data = NULL;
	}
}



static void
scsi_init_protocol(void)
{
	/*
	 * First, free up the data for the addresses attached to
	 * scsi_devtype_key_t structures.  Do so before we free
	 * those structures or destroy the hash table in which
	 * they're stored.
	 */
	if (scsidev_req_hash != NULL) {
		g_hash_table_foreach(scsidev_req_hash, free_devtype_key_dev_info,
		    NULL);
	}

	if (scsi_req_hash)
            g_hash_table_destroy(scsi_req_hash);
        if (scsidev_req_hash)
            g_hash_table_destroy (scsidev_req_hash);

	scsi_req_hash = g_hash_table_new(scsi_hash, scsi_equal);
        scsidev_req_hash = g_hash_table_new (scsidev_hash, scsidev_equal);
}

static void
dissect_scsi_evpd (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint offset, guint tot_len _U_)
{
    proto_tree *evpd_tree;
    proto_item *ti;
    guint pcode, plen, i, idlen;
    guint8 codeset, flags;

    if (tree) {
        pcode = tvb_get_guint8 (tvb, offset+1);
        plen = tvb_get_guint8 (tvb, offset+3);
        ti = proto_tree_add_text (tree, tvb, offset, plen+4, "Page Code: %s",
                                  val_to_str (pcode, scsi_evpd_pagecode_val,
                                              "Unknown (0x%08x)"));
        evpd_tree = proto_item_add_subtree (ti, ett_scsi_page);

        proto_tree_add_item (evpd_tree, hf_scsi_inq_qualifier, tvb, offset,
                             1, 0);
        proto_tree_add_item (evpd_tree, hf_scsi_inq_devtype, tvb, offset,
                             1, 0);
        proto_tree_add_text (evpd_tree, tvb, offset+1, 1,
                             "Page Code: %s",
                             val_to_str (pcode, scsi_evpd_pagecode_val,
                                         "Unknown (0x%02x)"));
        proto_tree_add_text (evpd_tree, tvb, offset+3, 1,
                             "Page Length: %u", plen);
        offset += 4;
        switch (pcode) {
        case SCSI_EVPD_SUPPPG:
            for (i = 0; i < plen; i++) {
                proto_tree_add_text (evpd_tree, tvb, offset+i, 1,
                                     "Supported Page: %s",
                                     val_to_str (tvb_get_guint8 (tvb, offset+i),
                                                 scsi_evpd_pagecode_val,
                                                 "Unknown (0x%02x)"));
            }
            break;
        case SCSI_EVPD_DEVID:
            while (plen != 0) {
                codeset = tvb_get_guint8 (tvb, offset) & 0x0F;
                proto_tree_add_text (evpd_tree, tvb, offset, 1,
                                     "Code Set: %s",
                                     val_to_str (codeset,
                                                 scsi_devid_codeset_val,
                                                 "Unknown (0x%02x)"));
                plen -= 1;
                offset += 1;

                if (plen < 1) {
                    proto_tree_add_text (evpd_tree, tvb, offset, 0,
                                         "Product data goes past end of page");
                    break;
                }
                flags = tvb_get_guint8 (tvb, offset);
                proto_tree_add_text (evpd_tree, tvb, offset, 1,
                                     "Association: %s",
                                     val_to_str ((flags & 0x30) >> 4,
                                                 scsi_devid_assoc_val,
                                                 "Unknown (0x%02x)"));
                proto_tree_add_text (evpd_tree, tvb, offset, 1,
                                     "Identifier Type: %s",
                                     val_to_str ((flags & 0x0F),
                                                 scsi_devid_idtype_val,
                                                 "Unknown (0x%02x)"));
                plen -= 1;
                offset += 1;

                /* Skip reserved byte */
                if (plen < 1) {
                    proto_tree_add_text (evpd_tree, tvb, offset, 0,
                                         "Product data goes past end of page");
                    break;
                }
                plen -= 1;
                offset += 1;

                if (plen < 1) {
                    proto_tree_add_text (evpd_tree, tvb, offset, 0,
                                         "Product data goes past end of page");
                    break;
                }
                idlen = tvb_get_guint8 (tvb, offset);
                proto_tree_add_text (evpd_tree, tvb, offset, 1,
                                     "Identifier Length: %u", idlen);
                plen -= 1;
                offset += 1;

                if (idlen != 0) {
                    if (plen < idlen) {
                        proto_tree_add_text (evpd_tree, tvb, offset, 0,
                                             "Product data goes past end of page");
                        break;
                    }
                    if (codeset == CODESET_ASCII) {
                        proto_tree_add_text (evpd_tree, tvb, offset, idlen,
                                             "Identifier: %s",
                                             tvb_format_text (tvb, offset,
                                                              idlen));
                    } else {
                        /*
                         * XXX - decode this based on the identifier type,
                         * if the codeset is CODESET_BINARY?
                         */
                        proto_tree_add_text (evpd_tree, tvb, offset, idlen,
                                             "Identifier: %s",
                                             tvb_bytes_to_str (tvb, offset,
                                                               idlen));
                    }
                    plen -= idlen;
                    offset += idlen;
                }
            }
            break;
        case SCSI_EVPD_DEVSERNUM:
            if (plen > 0) {
                proto_tree_add_text (evpd_tree, tvb, offset, plen,
                                     "Product Serial Number: %s",
                                     tvb_format_text (tvb, offset, plen));
            }
            break;
        }
    }
}

static void
dissect_scsi_cmddt (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, guint tot_len _U_)
{
    proto_tree *cmdt_tree;
    proto_item *ti;
    guint plen;

    if (tree) {
        plen = tvb_get_guint8 (tvb, offset+5);
        ti = proto_tree_add_text (tree, tvb, offset, plen, "Command Data");
        cmdt_tree = proto_item_add_subtree (ti, ett_scsi_page);

        proto_tree_add_item (cmdt_tree, hf_scsi_inq_qualifier, tvb, offset,
                             1, 0);
        proto_tree_add_item (cmdt_tree, hf_scsi_inq_devtype, tvb, offset,
                             1, 0);
        proto_tree_add_text (cmdt_tree, tvb, offset+1, 1, "Support: %s",
                             match_strval (tvb_get_guint8 (tvb, offset+1) & 0x7,
                                           scsi_cmdt_supp_val));
        proto_tree_add_text (cmdt_tree, tvb, offset+2, 1, "Version: %s",
                             val_to_str (tvb_get_guint8 (tvb, offset+2),
                                         scsi_verdesc_val,
                                         "Unknown (0x%02x)"));
        proto_tree_add_text (cmdt_tree, tvb, offset+5, 1, "CDB Size: %u",
                             plen);
    }
}

static void
dissect_spc3_inquiry (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint32 payload_len, scsi_task_data_t *cdata)
{
    guint8 flags, i, devtype;
    guint tot_len;
    scsi_devtype_data_t *devdata = NULL;
    scsi_devtype_key_t dkey, *req_key;

    if (!isreq && (cdata == NULL || !(cdata->flags & 0x3))) {
        /*
         * INQUIRY response with device type information; add device type
         * to list of known devices & their types if not already known.
         *
         * We don't use COPY_ADDRESS because "dkey.devid" isn't
         * persistent, and therefore it can point to the stuff
         * in "pinfo->src".  (Were we to use COPY_ADDRESS, we'd
         * have to free the address data it allocated before we return.)
         */
        dkey.devid = pinfo->src;
        devdata = (scsi_devtype_data_t *)g_hash_table_lookup (scsidev_req_hash,
                                                              &dkey);
        if (!devdata) {
            req_key = se_alloc (sizeof(scsi_devtype_key_t));
            COPY_ADDRESS (&(req_key->devid), &(pinfo->src));

            devdata = se_alloc (sizeof(scsi_devtype_data_t));
            devdata->devtype = tvb_get_guint8 (tvb, offset) & SCSI_DEV_BITS;

            g_hash_table_insert (scsidev_req_hash, req_key, devdata);
	}
        else {
            devtype = tvb_get_guint8 (tvb, offset);
            if ((devtype & SCSI_DEV_BITS) != SCSI_DEV_NOLUN) {
                /* Some initiators probe more than the available LUNs which
                 * results in Inquiry data being returned indicating that a LUN
                 * is not supported. We don't want to overwrite the device type
                 * with such responses.
                 */
                devdata->devtype = (devtype & SCSI_DEV_BITS);
            }
        }
    }

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        if (cdata != NULL) {
            cdata->flags = flags;
        }

        proto_tree_add_uint_format (tree, hf_scsi_inquiry_flags, tvb, offset, 1,
                                    flags, "CMDT = %u, EVPD = %u",
                                    flags & 0x2, flags & 0x1);
        if (flags & 0x1) {
            proto_tree_add_item (tree, hf_scsi_inquiry_evpd_page, tvb, offset+1,
                                 1, 0);
        }
        else if (flags & 0x2) {
            proto_tree_add_item (tree, hf_scsi_inquiry_cmdt_page, tvb, offset+1,
                                 1, 0);
        }

        proto_tree_add_item (tree, hf_scsi_alloclen, tvb, offset+3, 1, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq) {
        if (cdata && (cdata->flags & 0x1)) {
            dissect_scsi_evpd (tvb, pinfo, tree, offset, payload_len);
            return;
        }
        else if (cdata && (cdata->flags & 0x2)) {
            dissect_scsi_cmddt (tvb, pinfo, tree, offset, payload_len);
            return;
        }

        proto_tree_add_item (tree, hf_scsi_inq_qualifier, tvb, offset,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_inq_devtype, tvb, offset, 1, 0);
	proto_tree_add_item (tree, hf_scsi_inq_rmb,  tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_inq_version, tvb, offset+2, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_item_hidden (tree, hf_scsi_inq_normaca, tvb,
                                    offset+3, 1, 0);
        proto_tree_add_text (tree, tvb, offset+3, 1, "NormACA: %u, HiSup: %u",
                             ((flags & 0x20) >> 5), ((flags & 0x10) >> 4));
        tot_len = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1, "Additional Length: %u",
                             tot_len);
        flags = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "BQue: %u, SES: %u, MultiP: %u, Addr16: %u",
                             ((flags & 0x80) >> 7), (flags & 0x40) >> 6,
                             (flags & 0x10) >> 4, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "RelAdr: %u, Linked: %u, CmdQue: %u",
                             (flags & 0x80) >> 7, (flags & 0x08) >> 3,
                             (flags & 0x02) >> 1);
        proto_tree_add_text (tree, tvb, offset+8, 8, "Vendor Id: %s",
                             tvb_format_stringzpad (tvb, offset+8, 8));
        proto_tree_add_text (tree, tvb, offset+16, 16, "Product ID: %s",
                             tvb_format_stringzpad (tvb, offset+16, 16));
        proto_tree_add_text (tree, tvb, offset+32, 4, "Product Revision: %s",
                             tvb_format_stringzpad (tvb, offset+32, 4));

        offset += 58;
        if ((tot_len > 58) && tvb_bytes_exist (tvb, offset, 16)) {
            for (i = 0; i < 8; i++) {
                proto_tree_add_text (tree, tvb, offset, 2,
                                     "Vendor Descriptor %u: %s",
                                     i,
                                     val_to_str (tvb_get_ntohs (tvb, offset),
                                                 scsi_verdesc_val,
                                                 "Unknown (0x%04x)"));
                offset += 2;
            }
        }
    }
}

static void
dissect_spc3_extcopy (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
		      proto_tree *tree _U_, guint offset _U_,
		      gboolean isreq _U_, gboolean iscdb _U_,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

static void
dissect_spc3_logselect (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_logsel_flags, tvb, offset, 1,
                                    flags, "PCR = %u, SP = %u", flags & 0x2,
                                    flags & 0x1);
        proto_tree_add_uint_format (tree, hf_scsi_logsel_pc, tvb, offset+1, 1,
                                    tvb_get_guint8 (tvb, offset+1),
                                    "PC: 0x%x", flags & 0xC0);
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else {
    }
}

static void
dissect_spc3_logsense (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_logsns_flags, tvb, offset, 1,
                                    flags, "PPC = %u, SP = %u", flags & 0x2,
                                    flags & 0x1);
        proto_tree_add_uint_format (tree, hf_scsi_logsns_pc, tvb, offset+1, 1,
                                    tvb_get_guint8 (tvb, offset+1),
                                    "PC: 0x%x", flags & 0xC0);
        proto_tree_add_item (tree, hf_scsi_logsns_pagecode, tvb, offset+1,
                             1, 0);
        proto_tree_add_text (tree, tvb, offset+4, 2, "Parameter Pointer: 0x%04x",
                             tvb_get_ntohs (tvb, offset+4));
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else {
    }
}

static void
dissect_scsi_blockdescs (tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *scsi_tree,
                        scsi_task_data_t *cdata, gboolean longlba)
{
    int offset=0;

    /* without cdata there is no point in continuing */
    if (!cdata)
        return;

    while (tvb_length_remaining(tvb, offset)) {
        if (longlba) {
            if(tvb_length_remaining(tvb, offset)<8)
                return;
            proto_tree_add_text (scsi_tree, tvb, offset, 8, "No. of Blocks: %" PRIu64,
                                 tvb_get_ntoh64 (tvb, offset));
            offset += 8;

            if(tvb_length_remaining(tvb, offset)<1)
                return;
            proto_tree_add_text (scsi_tree, tvb, offset, 1, "Density Code: 0x%02x",
                                 tvb_get_guint8 (tvb, offset));
            offset += 1;

            /* 3 reserved bytes */
            offset += 3;

            if(tvb_length_remaining(tvb, offset)<4)
                return;
            proto_tree_add_text (scsi_tree, tvb, offset, 4, "Block Length: %u",
                                     tvb_get_ntohl (tvb, offset));
            offset += 4;
        } else {
            if (cdata->devtype == SCSI_DEV_SBC) {
                if(tvb_length_remaining(tvb, offset)<4)
                    return;
                proto_tree_add_text (scsi_tree, tvb, offset, 4, "No. of Blocks: %u",
                                     tvb_get_ntohl (tvb, offset));
                offset += 4;

		offset++;  /* reserved */

                if(tvb_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_text (scsi_tree, tvb, offset, 3, "Block Length: %u",
                                         tvb_get_ntoh24 (tvb, offset));
                offset += 3;
            } else {
                if(tvb_length_remaining(tvb, offset)<1)
                    return;
                proto_tree_add_text (scsi_tree, tvb, offset, 1, "Density Code: 0x%02x",
                                     tvb_get_guint8 (tvb, offset));
                offset += 1;

                if(tvb_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_text (scsi_tree, tvb, offset, 3, "No. of Blocks: %u",
                                     tvb_get_ntohl (tvb, offset));
                offset += 3;

		offset++; /* reserved */

                if(tvb_length_remaining(tvb, offset)<3)
                    return;
                proto_tree_add_text (scsi_tree, tvb, offset, 3, "Block Length: %u",
                                         tvb_get_ntoh24 (tvb, offset));
                offset += 3;
            }
        }
    }
}

static gboolean
dissect_scsi_spc2_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
		            proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags, proto;

    switch (pcode) {
    case SCSI_SPC2_MODEPAGE_CTL:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_item (tree, hf_scsi_modesns_tst, tvb, offset+2, 1, 0);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Global Logging Target Save Disable: %u, Report Log Exception Condition: %u",
                             (flags & 0x2) >> 1, (flags & 0x1));
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_item (tree, hf_scsi_modesns_qmod, tvb, offset+3, 1, 0);
        proto_tree_add_item (tree, hf_scsi_modesns_qerr, tvb, offset+3, 1, 0);
        proto_tree_add_text (tree, tvb, offset+3, 1, "Disable Queuing: %u",
                             flags & 0x1);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_item (tree, hf_scsi_modesns_rac, tvb, offset+4, 1, 0);
        proto_tree_add_item (tree, hf_scsi_modesns_tas, tvb, offset+4, 1, 0);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "SWP: %u, RAERP: %u, UAAERP: %u, EAERP: %u",
                             (flags & 0x8) >> 3, (flags & 0x4) >> 2,
                             (flags & 0x2) >> 2, (flags & 0x1));
        proto_tree_add_text (tree, tvb, offset+5, 1, "Autoload Mode: 0x%x",
                             tvb_get_guint8 (tvb, offset+5) & 0x7);
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Ready AER Holdoff Period: %u ms",
                             tvb_get_ntohs (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+8, 2,
                             "Busy Timeout Period: %u ms",
                             tvb_get_ntohs (tvb, offset+8)*100);
        proto_tree_add_text (tree, tvb, offset+10, 2,
                             "Extended Self-Test Completion Time: %u",
                             tvb_get_ntohs (tvb, offset+10));
        break;
    case SCSI_SPC2_MODEPAGE_DISCON:
        proto_tree_add_text (tree, tvb, offset+2, 1, "Buffer Full Ratio: %u",
                             tvb_get_guint8 (tvb, offset+2));
        proto_tree_add_text (tree, tvb, offset+3, 1, "Buffer Empty Ratio: %u",
                             tvb_get_guint8 (tvb, offset+3));
        proto_tree_add_text (tree, tvb, offset+4, 2, "Bus Inactivity Limit: %u",
                             tvb_get_ntohs (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+6, 2, "Disconnect Time Limit: %u",
                             tvb_get_ntohs (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+8, 2, "Connect Time Limit: %u",
                             tvb_get_ntohs (tvb, offset+8));
        proto_tree_add_text (tree, tvb, offset+10, 2,
                             "Maximum Burst Size: %u bytes",
                             tvb_get_ntohs (tvb, offset+10)*512);
        flags = tvb_get_guint8 (tvb, offset+12);
        proto_tree_add_text (tree, tvb, offset+12, 1,
                             "EMDP: %u, FAA: %u, FAB: %u, FAC: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4);
        proto_tree_add_text (tree, tvb, offset+14, 2,
                             "First Burst Size: %u bytes",
                             tvb_get_ntohs (tvb, offset+14)*512);
        break;
    case SCSI_SPC2_MODEPAGE_INFOEXCP:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Perf: %u, EBF: %u, EWasc: %u, DExcpt: %u, Test: %u, LogErr: %u",
                             (flags & 0x80) >> 7, (flags & 0x20) >> 5,
                             (flags & 0x10) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x01));
        if (!((flags & 0x10) >> 4) && ((flags & 0x08) >> 3)) {
            proto_tree_add_item_hidden (tree, hf_scsi_modesns_errrep, tvb,
                                        offset+3, 1, 0);
        }
        else {
            proto_tree_add_item (tree, hf_scsi_modesns_errrep, tvb, offset+3, 1, 0);
        }
        proto_tree_add_text (tree, tvb, offset+4, 4, "Interval Timer: %u",
                             tvb_get_ntohl (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+8, 4, "Report Count: %u",
                             tvb_get_ntohl (tvb, offset+8));
        break;
    case SCSI_SPC2_MODEPAGE_PWR:
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1, "Idle: %u, Standby: %u",
                             (flags & 0x2) >> 1, (flags & 0x1));
        proto_tree_add_text (tree, tvb, offset+4, 2,
                             "Idle Condition Timer: %u ms",
                             tvb_get_ntohs (tvb, offset+4) * 100);
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Standby Condition Timer: %u ms",
                             tvb_get_ntohs (tvb, offset+6) * 100);
        break;
    case SCSI_SPC2_MODEPAGE_LUN:
        return FALSE;
    case SCSI_SPC2_MODEPAGE_PORT:
        proto = tvb_get_guint8 (tvb, offset+2) & 0x0F;
        proto_tree_add_item (tree, hf_scsi_protocol, tvb, offset+2, 1, 0);
        if (proto == SCSI_PROTO_FCP) {
            flags = tvb_get_guint8 (tvb, offset+3);
            proto_tree_add_text (tree, tvb, offset+3, 1,
                                 "DTFD: %u, PLPB: %u, DDIS: %u, DLM: %u, RHA: %u, ALWI: %u, DTIPE: %u, DTOLI:%u",
                                 (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                                 (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                                 (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                                 (flags & 0x02) >> 1, (flags & 0x1));
            proto_tree_add_text (tree, tvb, offset+6, 1, "RR_TOV Units: %s",
                                 val_to_str (tvb_get_guint8 (tvb, offset+6) & 0x7,
                                             scsi_fcp_rrtov_val,
                                             "Unknown (0x%02x)"));
            proto_tree_add_text (tree, tvb, offset+7, 1, "RR_TOV: %u",
                                 tvb_get_guint8 (tvb, offset+7));
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
dissect_scsi_sbc2_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
		            proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags;

    switch (pcode) {
    case SCSI_SBC2_MODEPAGE_FMTDEV:
        proto_tree_add_text (tree, tvb, offset+2, 2, "Tracks Per Zone: %u",
                             tvb_get_ntohs (tvb, offset+2));
        proto_tree_add_text (tree, tvb, offset+4, 2,
                             "Alternate Sectors Per Zone: %u",
                             tvb_get_ntohs (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Alternate Tracks Per Zone: %u",
                             tvb_get_ntohs (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+8, 2,
                             "Alternate Tracks Per LU: %u",
                             tvb_get_ntohs (tvb, offset+8));
        proto_tree_add_text (tree, tvb, offset+10, 2, "Sectors Per Track: %u",
                             tvb_get_ntohs (tvb, offset+10));
        proto_tree_add_text (tree, tvb, offset+12, 2,
                             "Data Bytes Per Physical Sector: %u",
                             tvb_get_ntohs (tvb, offset+12));
        proto_tree_add_text (tree, tvb, offset+14, 2, "Interleave: %u",
                             tvb_get_ntohs (tvb, offset+14));
        proto_tree_add_text (tree, tvb, offset+16, 2, "Track Skew Factor: %u",
                             tvb_get_ntohs (tvb, offset+16));
        proto_tree_add_text (tree, tvb, offset+18, 2,
                             "Cylinder Skew Factor: %u",
                             tvb_get_ntohs (tvb, offset+18));
        flags = tvb_get_guint8 (tvb, offset+20);
        proto_tree_add_text (tree, tvb, offset+20, 1,
                             "SSEC: %u, HSEC: %u, RMB: %u, SURF: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4);
        break;
    case SCSI_SBC2_MODEPAGE_RDWRERR:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "AWRE: %u, ARRE: %u, TB: %u, RC: %u, EER: %u, PER: %u, DTE: %u, DCR: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        proto_tree_add_text (tree, tvb, offset+3, 1, "Read Retry Count: %u",
                             tvb_get_guint8 (tvb, offset+3));
        proto_tree_add_text (tree, tvb, offset+4, 1, "Correction Span: %u",
                             tvb_get_guint8 (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+5, 1, "Head Offset Count: %u",
                             tvb_get_guint8 (tvb, offset+5));
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "Data Strobe Offset Count: %u",
                             tvb_get_guint8 (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+8, 1, "Write Retry Count: %u",
                             tvb_get_guint8 (tvb, offset+8));
        proto_tree_add_text (tree, tvb, offset+10, 2,
                             "Recovery Time Limit: %u ms",
                             tvb_get_ntohs (tvb, offset+10));
        break;
   case SCSI_SBC2_MODEPAGE_DISKGEOM:
        proto_tree_add_text (tree, tvb, offset+2, 3, "Number of Cylinders: %u",
                             tvb_get_ntoh24 (tvb, offset+2));
        proto_tree_add_text (tree, tvb, offset+5, 1, "Number of Heads: %u",
                             tvb_get_guint8 (tvb, offset+5));
        proto_tree_add_text (tree, tvb, offset+6, 3,
                             "Starting Cyl Pre-compensation: %u",
                             tvb_get_ntoh24 (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+9, 3,
                             "Starting Cyl-reduced Write Current: %u",
                             tvb_get_ntoh24 (tvb, offset+9));
        proto_tree_add_text (tree, tvb, offset+12, 2, "Device Step Rate: %u",
                             tvb_get_ntohs (tvb, offset+12));
        proto_tree_add_text (tree, tvb, offset+14, 3, "Landing Zone Cyl: %u",
                             tvb_get_ntoh24 (tvb, offset+14));
        proto_tree_add_text (tree, tvb, offset+18, 1, "Rotational Offset: %u",
                             tvb_get_guint8 (tvb, offset+18));
        proto_tree_add_text (tree, tvb, offset+20, 2,
                             "Medium Rotation Rate: %u",
                             tvb_get_ntohs (tvb, offset+20));
        break;
    case SCSI_SBC2_MODEPAGE_FLEXDISK:
        return FALSE;
    case SCSI_SBC2_MODEPAGE_VERERR:
        return FALSE;
    case SCSI_SBC2_MODEPAGE_CACHE:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "IC: %u, ABPF: %u, CAP %u, Disc: %u, Size: %u, WCE: %u, MF: %u, RCD: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Demand Read Retention Priority: %u, Write Retention Priority: %u",
                             (flags & 0xF0) >> 4, (flags & 0x0F));
        proto_tree_add_text (tree, tvb, offset+4, 2,
                             "Disable Pre-fetch Xfer Len: %u",
                             tvb_get_ntohs (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+6, 2, "Minimum Pre-Fetch: %u",
                             tvb_get_ntohs (tvb, offset+6));
        proto_tree_add_text (tree, tvb, offset+8, 2, "Maximum Pre-Fetch: %u",
                             tvb_get_ntohs (tvb, offset+8));
        proto_tree_add_text (tree, tvb, offset+10, 2,
                             "Maximum Pre-Fetch Ceiling: %u",
                             tvb_get_ntohs (tvb, offset+10));
        flags = tvb_get_guint8 (tvb, offset+12);
        proto_tree_add_text (tree, tvb, offset+12, 1,
                             "FSW: %u, LBCSS: %u, DRA: %u, Vendor Specific: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x1F) >> 4);
        proto_tree_add_text (tree, tvb, offset+13, 1,
                             "Number of Cache Segments: %u",
                             tvb_get_guint8 (tvb, offset+13));
        proto_tree_add_text (tree, tvb, offset+14, 2, "Cache Segment Size: %u",
                             tvb_get_ntohs (tvb, offset+14));
        proto_tree_add_text (tree, tvb, offset+17, 3,
                             "Non-Cache Segment Size: %u",
                             tvb_get_ntoh24 (tvb, offset+17));
        break;
    case SCSI_SBC2_MODEPAGE_MEDTYPE:
        return FALSE;
    case SCSI_SBC2_MODEPAGE_NOTPART:
        return FALSE;
    case SCSI_SBC2_MODEPAGE_XORCTL:
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
dissect_scsi_ssc2_modepage (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
		            proto_tree *tree _U_, guint offset _U_,
                            guint8 pcode)
{
    guint8 flags;

    switch (pcode) {
    case SCSI_SSC2_MODEPAGE_DATACOMP:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "DCE: %u, DCC: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6);
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "DDE: %u, RED: %u",
                             (flags & 0x80) >> 7, (flags & 0x60) >> 5);
        proto_tree_add_text (tree, tvb, offset+4, 4,
                             "Compression algorithm: %s",
                             val_to_str (tvb_get_ntohl (tvb, offset+4),
                                         compression_algorithm_vals,
                                         "Unknown (0x%08x)"));
        proto_tree_add_text (tree, tvb, offset+8, 4,
                             "Decompression algorithm: %s",
                             val_to_str (tvb_get_ntohl (tvb, offset+4),
                                         compression_algorithm_vals,
                                         "Unknown (0x%08x)"));
        break;
    case SCSI_SSC2_MODEPAGE_DEVCONF:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "CAF: %u, Active Format: %u",
                             (flags & 0x20) >> 5, (flags & 0x1f));
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Active Partition: %u",
                             flags);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "Write Object Buffer Full Ratio: %u",
                             flags);
        flags = tvb_get_guint8 (tvb, offset+5);
        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "Read Object Buffer Empty Ratio: %u",
                             flags);
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Write Delay time: %u 100ms",
                             tvb_get_ntohs (tvb, offset+6));
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_text (tree, tvb, offset+8, 1,
                             "OBR: %u, LOIS: %u, RSMK: %u, AVC: %u, SOCF: %u, ROBO: %u, REW: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x0c) >> 2, (flags & 0x02) >> 1,
			     (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1,
                             "Gap Size: %u",
                             flags);
        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_text (tree, tvb, offset+10, 1,
                             "EOD Defined: %u, EEG: %u, SEW: %u, SWP: %u, BAML: %u, BAM: %u",
                             (flags & 0xe0) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        proto_tree_add_text (tree, tvb, offset+11, 3,
                             "Object Buffer Size At Early Warning: %u",
                             tvb_get_ntohs (tvb, offset+11));
        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_text (tree, tvb, offset+14, 1,
                             "Select Data Compression Algorithm: %u",
                             flags);
        flags = tvb_get_guint8 (tvb, offset+15);
        proto_tree_add_text (tree, tvb, offset+15, 1,
                             "OIR: %u, ReWind on Reset: %u, ASOCWP: %u, PERSWP: %u, PRMWP: %u",
                             (flags & 0x20) >> 5, (flags & 0x18) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1,
                             (flags & 0x01));
        break;
    case SCSI_SSC2_MODEPAGE_MEDPAR1:
        return FALSE;
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
dissect_scsi_mmc5_modepage (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
		            proto_tree *tree _U_, guint offset _U_, guint8 pcode)
{
    switch (pcode) {
    case SCSI_MMC3_MODEPAGE_MMCAP:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

static gboolean
dissect_scsi_smc2_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
		            proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags;
    guint8 param_list_len;

    switch (pcode) {
    case SCSI_SMC2_MODEPAGE_EAA:
        param_list_len = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1, "Parameter List Length: %u",
                             param_list_len);
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+3, 2, "First Medium Transport Element Address: %u",
                             tvb_get_ntohs (tvb, offset+3));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+5, 2, "Number of Medium Transport Elements: %u",
                             tvb_get_ntohs (tvb, offset+5));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+7, 2, "First Storage Element Address: %u",
                             tvb_get_ntohs (tvb, offset+7));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+9, 2, "Number of Storage Elements: %u",
                             tvb_get_ntohs (tvb, offset+9));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+11, 2, "First Import/Export Element Address: %u",
                             tvb_get_ntohs (tvb, offset+11));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+13, 2, "Number of Import/Export Elements: %u",
                             tvb_get_ntohs (tvb, offset+13));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+15, 2, "First Data Transfer Element Address: %u",
                             tvb_get_ntohs (tvb, offset+15));
        param_list_len -= 2;
        if (param_list_len < 2)
            break;
        proto_tree_add_text (tree, tvb, offset+17, 2, "Number of Data Transfer Elements: %u",
                             tvb_get_ntohs (tvb, offset+17));
        break;
    case SCSI_SMC2_MODEPAGE_TRANGEOM:
        return FALSE;
    case SCSI_SMC2_MODEPAGE_DEVCAP:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "STORDT: %u, STORI/E: %u, STORST: %u, STORMT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "MT->DT: %u, MT->I/E: %u, MT->ST: %u, MT->MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+5);
        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "ST->DT: %u, ST->I/E: %u, ST->ST: %u, ST->MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "I/E->DT: %u, I/E->I/E: %u, I/E->ST: %u, I/E->MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "DT->DT: %u, DT->I/E: %u, DT->ST: %u, DT->MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+12);
        proto_tree_add_text (tree, tvb, offset+12, 1,
                             "MT<>DT: %u, MT<>I/E: %u, MT<>ST: %u, MT<>MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+13);
        proto_tree_add_text (tree, tvb, offset+13, 1,
                             "ST<>DT: %u, ST<>I/E: %u, ST<>ST: %u, ST<>MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_text (tree, tvb, offset+14, 1,
                             "I/E<>DT: %u, I/E<>I/E: %u, I/E<>ST: %u, I/E<>MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+15);
        proto_tree_add_text (tree, tvb, offset+15, 1,
                             "DT<>DT: %u, DT<>I/E: %u, DT<>ST: %u, DT<>MT: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

static guint
dissect_scsi_modepage (tvbuff_t *tvb, packet_info *pinfo,
		       proto_tree *scsi_tree, guint offset,
                       scsi_device_type devtype)
{
    guint8 pcode, plen;
    proto_tree *tree;
    proto_item *ti;
    const value_string *modepage_val;
    int hf_pagecode;
    gboolean (*dissect_modepage)(tvbuff_t *, packet_info *, proto_tree *,
                                 guint, guint8);

    pcode = tvb_get_guint8 (tvb, offset);
    plen = tvb_get_guint8 (tvb, offset+1);

    if (match_strval (pcode & SCSI_MS_PCODE_BITS,
                      scsi_spc2_modepage_val) == NULL) {
        /*
         * This isn't a generic mode page that applies to all SCSI
         * device types; try to interpret it based on what we deduced,
         * or were told, the device type is.
         */
        switch (devtype) {
        case SCSI_DEV_SBC:
            modepage_val = scsi_sbc2_modepage_val;
            hf_pagecode = hf_scsi_sbcpagecode;
            dissect_modepage = dissect_scsi_sbc2_modepage;
            break;

        case SCSI_DEV_SSC:
            modepage_val = scsi_ssc2_modepage_val;
            hf_pagecode = hf_scsi_sscpagecode;
            dissect_modepage = dissect_scsi_ssc2_modepage;
            break;

        case SCSI_DEV_SMC:
            modepage_val = scsi_smc2_modepage_val;
            hf_pagecode = hf_scsi_smcpagecode;
            dissect_modepage = dissect_scsi_smc2_modepage;
            break;

        case SCSI_DEV_CDROM:
            modepage_val = scsi_mmc5_modepage_val;
            hf_pagecode = hf_scsi_mmcpagecode;
            dissect_modepage = dissect_scsi_mmc5_modepage;
            break;

        default:
            /*
             * The "val_to_str()" lookup will fail in this table
             * (it failed in "match_strval()"), so it'll return
             * "Unknown (XXX)", which is what we want.
             */
            modepage_val = scsi_spc2_modepage_val;
            hf_pagecode = hf_scsi_spcpagecode;
            dissect_modepage = dissect_scsi_spc2_modepage;
            break;
	}
    } else {
        modepage_val = scsi_spc2_modepage_val;
        hf_pagecode = hf_scsi_spcpagecode;
        dissect_modepage = dissect_scsi_spc2_modepage;
    }
    ti = proto_tree_add_text (scsi_tree, tvb, offset, plen+2, "%s Mode Page",
                              val_to_str (pcode & SCSI_MS_PCODE_BITS,
                                          modepage_val, "Unknown (0x%08x)"));
    tree = proto_item_add_subtree (ti, ett_scsi_page);
    proto_tree_add_text (tree, tvb, offset, 1, "PS: %u", (pcode & 0x80) >> 7);

    proto_tree_add_item (tree, hf_pagecode, tvb, offset, 1, 0);
    proto_tree_add_text (tree, tvb, offset+1, 1, "Page Length: %u",
                         plen);

    if (!tvb_bytes_exist (tvb, offset, plen)) {
    	/* XXX - why not just drive on and throw an exception? */
        return (plen + 2);
    }

    if (!(*dissect_modepage)(tvb, pinfo, tree, offset,
                             (guint8) (pcode & SCSI_MS_PCODE_BITS))) {
        proto_tree_add_text (tree, tvb, offset+2, plen,
                             "Unknown Page");
    }
    return (plen+2);
}

static void
dissect_spc3_modeselect6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len, scsi_task_data_t *cdata)
{
    guint8 flags;
    guint plen;
    gint tot_len, desclen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_modesel_flags, tvb, offset, 1,
                                    flags, "PF = %u, SP = %u", flags & 0x10,
                                    flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_paramlen, tvb, offset+3, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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
        tot_len = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1, "Mode Data Length: %d",
                             tot_len);
        offset += 1;
        payload_len -= 1;
        /* The mode data length is reserved for MODE SELECT, so we just
           use the payload length. */

        if (payload_len < 1)
            return;
        switch (cdata->devtype) {

        case SCSI_DEV_SBC:
            proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: %s",
                                 val_to_str(tvb_get_guint8 (tvb, offset),
                                            scsi_modesense_medtype_sbc_val,
                                            "Unknown (0x%02x)"));
            break;

        default:
            proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: 0x%02x",
                                 tvb_get_guint8 (tvb, offset));
            break;
        }
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        desclen = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Block Descriptor Length: %d", desclen);
        offset += 1;
        payload_len -= 1;

        if(tvb_length_remaining(tvb, offset)>0){
            blockdesc_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs (blockdesc_tvb, pinfo, tree, cdata, FALSE);
        }
        offset += desclen;
        payload_len -= desclen;

        /* offset points to the start of the mode page */
        while ((payload_len > 0) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->devtype);
            offset += plen;
            payload_len -= plen;
        }
    }
}

static void
dissect_spc3_modeselect10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len, scsi_task_data_t *cdata)
{
    guint8 flags;
    gboolean longlba;
    gint tot_len, desclen;
    guint plen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_modesel_flags, tvb, offset, 1,
                                    flags, "PF = %u, SP = %u", flags & 0x10,
                                    flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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
        tot_len = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2, "Mode Data Length: %u",
                             tot_len);
        offset += 2;
        payload_len -= 2;
        /* The mode data length is reserved for MODE SELECT, so we just
           use the payload length. */

        if (payload_len < 1)
            return;
        switch (cdata->devtype) {

        case SCSI_DEV_SBC:
            proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: %s",
                                 val_to_str(tvb_get_guint8 (tvb, offset),
                                            scsi_modesense_medtype_sbc_val,
                                            "Unknown (0x%02x)"));
            break;

        default:
            proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: 0x%02x",
                                 tvb_get_guint8 (tvb, offset));
            break;
        }
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        payload_len -= 1;

        if (payload_len < 1)
            return;
        longlba = tvb_get_guint8 (tvb, offset) & 0x1;
        proto_tree_add_text (tree, tvb, offset, 1, "LongLBA: %u", longlba);
        offset += 2;	/* skip LongLBA byte and reserved byte */
        payload_len -= 2;

        if (payload_len < 1)
            return;
        desclen = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Block Descriptor Length: %u", desclen);
        offset += 2;
        payload_len -= 2;

        if(tvb_length_remaining(tvb, offset)>0){
            blockdesc_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs (blockdesc_tvb, pinfo, tree, cdata, longlba);
        }
        offset += desclen;
        payload_len -= desclen;

        /* offset points to the start of the mode page */
        while ((payload_len > 0) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->devtype);
            offset += plen;
            payload_len -= plen;
        }
    }
}

static void
dissect_scsi_pagecode (tvbuff_t *tvb, packet_info *pinfo _U_,
                       proto_tree *tree, guint offset,
                       scsi_task_data_t *cdata)
{
    guint8 pcode;
    const gchar *valstr;
    int hf_pagecode;

    /* unless we have cdata there is not much point in continuing */
    if (!cdata)
        return;

    pcode = tvb_get_guint8 (tvb, offset);
    if ((valstr = match_strval (pcode & SCSI_MS_PCODE_BITS,
                                scsi_spc2_modepage_val)) == NULL) {
        /*
         * This isn't a generic mode page that applies to all SCSI
         * device types; try to interpret it based on what we deduced,
         * or were told, the device type is.
         */
        switch (cdata->devtype) {
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
            hf_pagecode = hf_scsi_spcpagecode;
            break;
	}
    } else {
        hf_pagecode = hf_scsi_spcpagecode;
    }
    proto_tree_add_uint (tree, hf_pagecode, tvb, offset, 1, pcode);
}

static void
dissect_spc3_modesense6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len, scsi_task_data_t *cdata)
{
    guint8 flags;
    guint plen;
    gint tot_len, desclen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                    flags, "DBD = %u", flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_modesns_pc, tvb, offset+1, 1, 0);
        dissect_scsi_pagecode (tvb, pinfo, tree, offset+1, cdata);
        proto_tree_add_item (tree, hf_scsi_alloclen, tvb, offset+3, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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
        tot_len = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1, "Mode Data Length: %u",
                             tot_len);
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
        proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        desclen = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Block Descriptor Length: %d", desclen);
        offset += 1;
        tot_len -= 1;


        if(tvb_length_remaining(tvb, offset)>0){
            blockdesc_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs (blockdesc_tvb, pinfo, tree, cdata, FALSE);
        }
        offset += desclen;
        tot_len -= desclen;

        /* offset points to the start of the mode page */
        while ((tot_len > 0) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->devtype);
            offset += plen;
            tot_len -= plen;
        }
    }
}

static void
dissect_spc3_modesense10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len, scsi_task_data_t *cdata)
{
    guint8 flags;
    gboolean longlba;
    gint tot_len, desclen;
    guint plen;
    tvbuff_t *blockdesc_tvb;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                    flags, "LLBAA = %u, DBD = %u", flags & 0x10,
                                    flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_modesns_pc, tvb, offset+1, 1, 0);
        dissect_scsi_pagecode (tvb, pinfo, tree, offset+1, cdata);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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
        tot_len = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2, "Mode Data Length: %u",
                             tot_len);
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
        proto_tree_add_text (tree, tvb, offset, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset));
        offset += 1;
        tot_len -= 1;

        if (tot_len < 1)
            return;
        longlba = tvb_get_guint8 (tvb, offset) & 0x1;
        proto_tree_add_text (tree, tvb, offset, 1, "LongLBA: %u", longlba);
        offset += 2;	/* skip LongLBA byte and reserved byte */
        tot_len -= 2;

        if (tot_len < 1)
            return;
        desclen = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Block Descriptor Length: %u", desclen);
        offset += 2;
        tot_len -= 2;

        if(tvb_length_remaining(tvb, offset)>0){
            blockdesc_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset),desclen), desclen);
            dissect_scsi_blockdescs (blockdesc_tvb, pinfo, tree, cdata, longlba);
        }
        offset += desclen;
        tot_len -= desclen;

        /* offset points to the start of the mode page */
        while ((tot_len > 0) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->devtype);
            offset += plen;
            tot_len -= plen;
        }
    }
}

static void
dissect_spc3_preventallowmediaremoval (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1, 
                             "Persistent: %u, Prevent: %u",
                             flags & 0x02, flags & 0x01);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_spc3_persistentreservein (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len, scsi_task_data_t *cdata)
{
    guint16 flags;
    int numrec, i;
    guint len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_persresvin_svcaction, tvb, offset+1,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
        /* We store the service action since we want to interpret the data */
        cdata->flags = tvb_get_guint8 (tvb, offset+1);
    }
    else {
        if (cdata) {
            flags = cdata->flags;
        }
        else {
            flags = 0xFF;
        }
        proto_tree_add_text (tree, tvb, offset, 4, "Generation Number: 0x%08x",
                             tvb_get_ntohl (tvb, offset));
        len = tvb_get_ntohl (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset, 4, "Additional Length: %u",
                             len);
        len = (payload_len > len) ? len : payload_len;

        if ((flags & 0x1F) == SCSI_SPC2_RESVIN_SVCA_RDKEYS) {
	    /* XXX - what if len is < 8?  That may be illegal, but
	       that doesn't make it impossible.... */
            numrec = (len - 8)/8;
            offset += 8;

            for (i = 0; i < numrec; i++) {
                proto_tree_add_item (tree, hf_scsi_persresv_key, tvb, offset,
                                     8, 0);
                offset -= 8;
            }
        }
        else if ((flags & 0x1F) == SCSI_SPC2_RESVIN_SVCA_RDRESV) {
            proto_tree_add_item (tree, hf_scsi_persresv_key, tvb, offset+8,
                                 8, 0);
            proto_tree_add_item (tree, hf_scsi_persresv_scopeaddr, tvb,
                                 offset+8, 4, 0);
            proto_tree_add_item (tree, hf_scsi_persresv_scope, tvb, offset+13,
                                 1, 0);
            proto_tree_add_item (tree, hf_scsi_persresv_type, tvb, offset+13,
                                 1, 0);
        }
    }
}

static void
dissect_spc3_persistentreserveout (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_persresvin_svcaction, tvb, offset,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_persresv_scope, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_persresv_type, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else {
    }
}

static void
dissect_spc2_release6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_spc2_release10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_release_flags, tvb, offset, 1,
                                    flags,
                                    "Flags: 3rd Party ID = %u, LongID = %u",
                                    flags & 0x10, flags & 0x2);
        if ((flags & 0x12) == 0x10) {
            proto_tree_add_item (tree, hf_scsi_release_thirdpartyid, tvb,
                                 offset+2, 1, 0);
        }
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_spc3_reportdeviceidentifier (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
proto_tree *tree _U_,
                  guint offset _U_, gboolean isreq _U_, gboolean iscdb _U_,
                  guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

static void
dissect_spc3_reportluns (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len, scsi_task_data_t *cdata _U_)
{
    guint8 flags;
    guint listlen, i;

    if (!tree)
        return;

    if (isreq && iscdb) {
	proto_tree_add_item (tree, hf_scsi_select_report, tvb, offset+1, 1, 0);

        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb, offset+5, 4, 0);

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq) {
        listlen = tvb_get_ntohl (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 4, "LUN List Length: %u",
                             listlen);
        offset += 8;
        payload_len -= 8;
        if (payload_len != 0) {
            listlen = (listlen < payload_len) ? listlen : payload_len;
        }

        for (i = 0; i < listlen/8; i++) {
            if (!tvb_get_guint8 (tvb, offset))
                proto_tree_add_item (tree, hf_scsi_rluns_lun, tvb, offset+1, 1,
                                     0);
            else
                proto_tree_add_item (tree, hf_scsi_rluns_multilun, tvb, offset,
                                     8, 0);
            offset += 8;
        }
    }
}

static void
dissect_scsi_fix_snsinfo (tvbuff_t *tvb, proto_tree *sns_tree, guint offset)
{
    guint8 flags;

    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (sns_tree, tvb, offset, 1, "Valid: %u",
                         (flags & 0x80) >> 7);
    proto_tree_add_item (sns_tree, hf_scsi_sns_errtype, tvb, offset, 1, 0);
    flags = tvb_get_guint8 (tvb, offset+2);
    proto_tree_add_text (sns_tree, tvb, offset+2, 1,
                             "Filemark: %u, EOM: %u, ILI: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5);
    proto_tree_add_item (sns_tree, hf_scsi_snskey, tvb, offset+2, 1, 0);
    proto_tree_add_item (sns_tree, hf_scsi_snsinfo, tvb, offset+3, 4, 0);
    proto_tree_add_item (sns_tree, hf_scsi_addlsnslen, tvb, offset+7, 1, 0);
    proto_tree_add_text (sns_tree, tvb, offset+8, 4,
                             "Command-Specific Information: %s",
                             tvb_bytes_to_str (tvb, offset+8, 4));
    proto_tree_add_item (sns_tree, hf_scsi_ascascq, tvb, offset+12, 2, 0);
    proto_tree_add_item_hidden (sns_tree, hf_scsi_asc, tvb, offset+12, 1, 0);
    proto_tree_add_item_hidden (sns_tree, hf_scsi_ascq, tvb, offset+13,
                                    1, 0);
    proto_tree_add_item (sns_tree, hf_scsi_fru, tvb, offset+14, 1, 0);
    proto_tree_add_item (sns_tree, hf_scsi_sksv, tvb, offset+15, 1, 0);
    proto_tree_add_text (sns_tree, tvb, offset+15, 3,
                             "Sense Key Specific: %s",
                             tvb_bytes_to_str (tvb, offset+15, 3));
}

static void
dissect_spc3_requestsense (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_alloclen, tvb, offset+3, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq)
	dissect_scsi_fix_snsinfo(tvb, tree, offset);
}

static void
dissect_spc2_reserve6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_spc2_reserve10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_release_flags, tvb, offset, 1,
                                    flags,
                                    "Flags: 3rd Party ID = %u, LongID = %u",
                                    flags & 0x10, flags & 0x2);
        if ((flags & 0x12) == 0x10) {
            proto_tree_add_item (tree, hf_scsi_release_thirdpartyid, tvb,
                                 offset+2, 1, 0);
        }
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                            guint offset, gboolean isreq _U_, gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree || !iscdb)
        return;

    proto_tree_add_boolean (tree, hf_scsi_ssu_immed, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_ssu_pwr_cond, tvb, offset+3, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_ssu_loej, tvb, offset+3, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_ssu_start, tvb, offset+3, 1, 0);

    flags = tvb_get_guint8 (tvb, offset+4);
    proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                flags,
                                "Vendor Unique = %u, NACA = %u, Link = %u",
                                flags & 0xC0, flags & 0x4, flags & 0x1);
}

static void
dissect_spc3_testunitready (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_formatunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_uint_format (tree, hf_scsi_formatunit_flags, tvb, offset,
                                    1, flags,
                                    "Flags: Longlist = %u, FMTDATA = %u, CMPLIST = %u",
                                    flags & 0x20, flags & 0x8, flags & 0x4);
        proto_tree_add_item (tree, hf_scsi_cdb_defectfmt, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_formatunit_vendor, tvb, offset+1,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_formatunit_interleave, tvb, offset+2,
                             2, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readwrite6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%06x, Len: %u)",
                             tvb_get_ntoh24 (tvb, offset),
                             tvb_get_guint8 (tvb, offset+3));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_rdwr6_lba, tvb, offset, 3, 0);
        proto_tree_add_item (tree, hf_scsi_rdwr6_xferlen, tvb, offset+3, 1, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readwrite10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_rdwr10_lba, tvb, offset+1, 4, 0);
        proto_tree_add_item (tree, hf_scsi_rdwr10_xferlen, tvb, offset+6, 2, 0);
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readwrite12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+5));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_rdwr10_lba, tvb, offset+1, 4, 0);
        proto_tree_add_item (tree, hf_scsi_rdwr12_xferlen, tvb, offset+5, 4, 0);
        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readwrite16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" PRIu64 ", Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_rdwr16_lba, tvb, offset+1, 8, 0);
        proto_tree_add_item (tree, hf_scsi_rdwr12_xferlen, tvb, offset+9, 4, 0);
        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_verify10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+2),
                             tvb_get_ntohs (tvb, offset+7));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_verify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_vlen, tvb, offset+7, 2, 0);
         flags = tvb_get_guint8 (tvb, offset+9);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+9, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_verify12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+2),
                             tvb_get_ntohl (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_verify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_vlen32, tvb, offset+6, 4, 0);
         flags = tvb_get_guint8 (tvb, offset+11);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+11, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_verify16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" PRIu64 ", Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+2),
                             tvb_get_ntohl (tvb, offset+10));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_verify_lba, tvb, offset+2, 8, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_vlen, tvb, offset+10, 4, 0);
         flags = tvb_get_guint8 (tvb, offset+15);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+15, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_wrverify10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+2),
                             tvb_get_ntohs (tvb, offset+7));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_xferlen, tvb, offset+7,
                              2, 0);
         flags = tvb_get_guint8 (tvb, offset+9);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+9, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_wrverify12 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+2),
                             tvb_get_ntohl (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_xferlen32, tvb, offset+6,
                              4, 0);
         flags = tvb_get_guint8 (tvb, offset+11);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+11, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_wrverify16 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" PRIu64 ", Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+2),
                             tvb_get_ntohl (tvb, offset+10));
    }

    if (tree && isreq && iscdb) {
         proto_tree_add_item (tree, hf_sbc2_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_sbc2_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_lba64, tvb, offset+2, 8, 0);
         proto_tree_add_item (tree, hf_sbc2_wrverify_xferlen32, tvb, offset+10,
                              4, 0);
         flags = tvb_get_guint8 (tvb, offset+15);
         proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+15, 1,
                                     flags,
                                     "Vendor Unique = %u, NACA = %u, Link = %u",
                                     flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static const value_string scsi_key_class_val[] = {
    {0x00, "DVD CSS/CPPM or CPRM"},
    {0x01, "ReWriteable Security Service - A"},
    {0,NULL}
};
static const value_string scsi_key_format_val[] = {
    {0x00,	"AGID for CSS/CPPM"},
    {0x01,	"Challenge Key"},
    {0x02,	"Key 1"},
    {0x04,	"Title Key"},
    {0x05,	"Authentication Success Flag"},
    {0x08,	"RPC State"},
    {0x11,	"AGID for CPRM"},
    {0x3f,	"None"},
    {0,NULL}
};
static const value_string scsi_report_key_type_code_val[] = {
    {0x00,	"NONE"},
    {0x01,	"SET"},
    {0x02,	"LAST CHANCE"},
    {0x03,	"PERM"},
    {0,NULL}
};
static const value_string scsi_report_key_rpc_scheme_val[] = {
    {0x00,	"Unknown (RPC not enforced)"},
    {0x01,	"RPC Phase II"},
    {0,NULL}
};

static void
dissect_mmc4_reportkey (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags, agid, key_format, key_class;
    proto_item *ti;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_lba, tvb, offset+1,
                             4, 0);
        key_class=tvb_get_guint8(tvb, offset+6);
        proto_tree_add_item (tree, hf_scsi_key_class, tvb, offset+6,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+7, 2, 0);

	agid=tvb_get_guint8(tvb, offset+9)&0xc0;
	key_format=tvb_get_guint8(tvb, offset+9)&0x3f;
	switch(key_format){
        case 0x01:
        case 0x02:
        case 0x04:
        case 0x3f:
            /* agid is only valid for some formats */
            proto_tree_add_uint (tree, hf_scsi_agid, tvb, offset+9, 1, agid);
            break;
        }
        proto_tree_add_uint (tree, hf_scsi_key_format, tvb, offset+9, 1, key_format);
	/* save key_class/key_format so we can decode the response */
	cdata->flags=(key_format<<8)|key_class;

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    if(tree && (!isreq)) {
        switch(cdata->flags){
        case 0x0800: /* format:RPC State  class:00 */
            proto_tree_add_item (tree, hf_scsi_data_length, tvb, offset, 2, 0);
            proto_tree_add_item (tree, hf_scsi_report_key_type_code, tvb, offset+4, 1, 0);
            proto_tree_add_item (tree, hf_scsi_report_key_vendor_resets, tvb, offset+4, 1, 0);
            proto_tree_add_item (tree, hf_scsi_report_key_user_changes, tvb, offset+4, 1, 0);
            proto_tree_add_item (tree, hf_scsi_report_key_region_mask, tvb, offset+5, 1, 0);
            proto_tree_add_item (tree, hf_scsi_report_key_rpc_scheme, tvb, offset+6, 1, 0);
            break;
        default:
	    ti = proto_tree_add_text (tree, tvb, 0, 0,
		"SCSI/MMC Unknown Format:0x%02x/Class:0x%02x combination",
		cdata->flags>>8,cdata->flags&0xff);
	    PROTO_ITEM_SET_GENERATED(ti);
	    break;
        }
    }
}

static const value_string scsi_setstreaming_type_val[] = {
    {0x00,	"Performance Descriptor"},
    {0x05,	"DBI cache zone descriptor"},
    {0,NULL}
};

static void
dissect_mmc4_setstreaming (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags, type;
    proto_item *ti;

    if (tree && isreq && iscdb) {
        type=tvb_get_guint8(tvb, offset+7);
	cdata->flags=type;
        proto_tree_add_item (tree, hf_scsi_setstreaming_type, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_setstreaming_param_len, tvb, offset+8, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    if(tree && isreq && (!iscdb)) {
        switch(cdata->flags){
        case 0x00: /* performance descriptor */
            proto_tree_add_item (tree, hf_scsi_setstreaming_wrc, tvb, offset+0, 1, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_rdd, tvb, offset+0, 1, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_exact, tvb, offset+0, 1, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_ra, tvb, offset+0, 1, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_start_lba, tvb, offset+4, 4, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_end_lba, tvb, offset+8, 4, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_read_size, tvb, offset+12, 4, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_read_time, tvb, offset+16, 4, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_write_size, tvb, offset+20, 4, 0);
            proto_tree_add_item (tree, hf_scsi_setstreaming_write_time, tvb, offset+24, 4, 0);
            break;
        default:
	    ti = proto_tree_add_text (tree, tvb, 0, 0,
		"SCSI/MMC Unknown SetStreaming Type:0x%02x",cdata->flags);
	    PROTO_ITEM_SET_GENERATED(ti);
	    break;
        }
    }
}

static const value_string scsi_setcdspeed_rc_val[] = {
    {0x00,	"CLV and none-pure CAV"},
    {0x01,	"Pure CAV"},
    {0x02,	"Reserved"},
    {0x03,	"Reserved"},
    {0,NULL}
};

static void
dissect_mmc4_setcdspeed (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_setcdspeed_rc, tvb, offset+0, 1, 0);

        proto_tree_add_text (tree, tvb, offset+1, 2,
                             "Logical Unit Read Speed(bytes/sec): %u",
                             tvb_get_ntohs (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+3, 2,
                             "Logical Unit Write Speed(bytes/sec): %u",
                             tvb_get_ntohs (tvb, offset+3));

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static const value_string scsi_getconf_rt_val[] = {
    {0x00,	"Return all features"},
    {0x01,	"Return all current features"},
    {0x02,	"Return all identified by Starting Feature"},
    {0,NULL}
};
static const value_string scsi_getconf_current_profile_val[] = {
    {0x0000,	"Reserved"},
    {0x0001,	"Non-removable disk"},
    {0x0002,	"Removable disk"},
    {0x0003,	"MO Erasable"},
    {0x0004,	"Optical Write Once"},
    {0x0005,	"AS-MO"},
    {0x0008,	"CD-ROM"},
    {0x0009,	"CD-R"},
    {0x000a,	"CD-RW"},
    {0x0010,	"DVD-ROM"},
    {0x0011,	"DVD-R"},
    {0x0012,	"DVD-RAM"},
    {0x0013,	"DVD-RW Restricted Overwrite"},
    {0x0014,	"DVD-RW Sequential recording"},
    {0x001a,	"DVD+RW"},
    {0x001b,	"DVD+R"},
    {0x0020,	"DDCD-ROM"},
    {0x0021,	"DDCD-R"},
    {0x0022,	"DDCD-RW"},
    {0xffff,	"Logical unit not conforming to a standard profile"},
    {0,NULL}
};

static const value_string scsi_feature_val[] = {
    {0x0000,	"Profile List"},
    {0x0001,	"Core"},
    {0x0002,	"Morphing"},
    {0x0003,	"Removable Medium"},
    {0x0004,	"Write Protect"},
    {0x0010,	"Random Readable"},
    {0x001d,	"Multi-read"},
    {0x001e,	"CD Read"},
    {0x001f,	"DVD Read"},
    {0x0020,	"Random Writeable"},
    {0x0021,	"Incremental Streaming Writeable"},
    {0x0022,	"Sector Erasable"},
    {0x0023,	"Formattable"},
    {0x0024,	"Defect Management"},
    {0x0025,	"Write Once"},
    {0x0026,	"Restricted Overwrite"},
    {0x0027,	"CD-RW CAV Write"},
    {0x0028,	"MRW"},
    {0x0029,	"Enhanced Defect Reporting"},
    {0x002a,	"DVD+RW"},
    {0x002b,	"DVD+R"},
    {0x002c,	"Rigid Restricted Overwrite"},
    {0x002d,	"CD Track At Once"},
    {0x002e,	"CD Mastering"},
    {0x002f,	"DVD-R/-RW Write"},
    {0x0030,	"DDCD Read"},
    {0x0031,	"DDCD-R Write"},
    {0x0032,	"DDCD-RW Write"},
    {0x0037,	"CD-RW Media Write Support"},
    {0x0100,	"Power Management"},
    {0x0101,	"SMART"},
    {0x0102,	"Embedded Changer"},
    {0x0103,	"CD Audio analog play"},
    {0x0104,	"Microcode Upgrade"},
    {0x0105,	"Timeout"},
    {0x0106,	"DVD-CSS"},
    {0x0107,	"Real Time Streaming"},
    {0x0108,	"Logical Unit serial number"},
    {0x010a,	"Disc control Block"},
    {0x010b,	"DVD CPRM"},
    {0x010c,	"Firmware Information"},
    {0,NULL}
};

static void
dissect_mmc4_getconfiguration (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;
    gint32 len;
    guint old_offset;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_getconf_rt, tvb, offset+0, 1, 0);
        proto_tree_add_item (tree, hf_scsi_getconf_starting_feature, tvb, offset+1, 2, 0);

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    if(tree && (!isreq)) {
        len=tvb_get_ntohl(tvb, offset+0);

	TRY_SCSI_SHORT_TRANSFER(pinfo, tvb, offset, len+4); 

        proto_tree_add_item (tree, hf_scsi_data_length, tvb, offset, 4, 0);
        proto_tree_add_item (tree, hf_scsi_getconf_current_profile, tvb, offset+6, 2, 0);
	offset+=8;
        len-=4;
        while(len>0){
                guint16 feature;
                guint8 additional_length;
		guint8 num_linksize;

                feature=tvb_get_ntohs(tvb, offset);
	        proto_tree_add_item (tree, hf_scsi_feature, tvb, offset, 2, 0);
                offset+=2;
	        proto_tree_add_item (tree, hf_scsi_feature_version, tvb, offset, 1, 0);
	        proto_tree_add_item (tree, hf_scsi_feature_persistent, tvb, offset, 1, 0);
	        proto_tree_add_item (tree, hf_scsi_feature_current, tvb, offset, 1, 0);
                offset+=1;
                additional_length=tvb_get_guint8(tvb, offset);
	        proto_tree_add_item (tree, hf_scsi_feature_additional_length, tvb, offset, 1, 0);
                offset+=1;
                old_offset=offset;
                switch(feature){
                case 0x0000: /* profile list */
                    while(offset<(old_offset+additional_length)){
			proto_item *it=NULL;
			proto_tree *tr=NULL;
			guint16 profile;
			guint8  cur_profile;

			if(tree){
				it=proto_tree_add_text(tree, tvb, offset, 4, "Profile:");
				tr=proto_item_add_subtree(it, ett_scsi_profile);
			}

			profile=tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item (tr, hf_scsi_feature_profile, tvb, offset, 2, 0);
			proto_item_append_text(it, "%s", val_to_str(profile, scsi_getconf_current_profile_val, "Unknown 0x%04x"));

			cur_profile=tvb_get_guint8(tvb, offset+2);
                        proto_tree_add_item (tr, hf_scsi_feature_profile_current, tvb, offset+2, 1, 0);
			if(cur_profile&0x01){
				proto_item_append_text(it, "  [CURRENT]");
			}

                        offset+=4;
                    }
                    break;
                case 0x001d: /* multi-read */
                case 0x001f: /* dvd read feature */
                    /* no data for this one */
                    break;
                case 0x001e: /* cd read */
                    proto_tree_add_item (tree, hf_scsi_feature_cdread_dap, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_cdread_c2flag, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_cdread_cdtext, tvb, offset, 1, 0);
                    break;
                case 0x0021: /* incremental streaming writeable */
                    proto_tree_add_item (tree, hf_scsi_feature_dts, tvb, offset, 2, 0);
                    offset+=2;
                    proto_tree_add_item (tree, hf_scsi_feature_isw_buf, tvb, offset, 1, 0);
                    offset+=1;
                    num_linksize=tvb_get_guint8(tvb, offset);
                    proto_tree_add_item (tree, hf_scsi_feature_isw_num_linksize, tvb, offset, 1, 0);
                    offset+=1;
                    while(num_linksize--){
                        proto_tree_add_item (tree, hf_scsi_feature_isw_linksize, tvb, offset, 1, 0);
                        offset+=1;
                    }
                    break;
                case 0x002a: /* dvd-rw */
                    proto_tree_add_item (tree, hf_scsi_feature_dvdrw_write, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_dvdrw_quickstart, tvb, offset, 2, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_dvdrw_closeonly, tvb, offset, 2, 0);
                    break;
                case 0x002b: /* dvd-r */
                    proto_tree_add_item (tree, hf_scsi_feature_dvdr_write, tvb, offset, 1, 0);
                    break;
                case 0x002d: /* track at once */
                    proto_tree_add_item (tree, hf_scsi_feature_tao_buf, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_tao_rwraw, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_tao_rwpack, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_tao_testwrite, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_tao_cdrw, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_tao_rwsubcode, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_dts, tvb, offset+2, 2, 0);
                    break;
                case 0x002e: /* session at once */
                    proto_tree_add_item (tree, hf_scsi_feature_sao_buf, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_sao, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_rawms, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_raw, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_testwrite, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_cdrw, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_rw, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_sao_mcsl, tvb, offset+1, 3, 0);
                    break;
                case 0x002f: /* dvd-r/-rw*/
                    proto_tree_add_item (tree, hf_scsi_feature_dvdr_buf, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_dvdr_testwrite, tvb, offset, 1, 0);
                    proto_tree_add_item (tree, hf_scsi_feature_dvdr_dvdrw, tvb, offset, 1, 0);
                    break;
                case 0x0108: /* logical unit serial number */
                    proto_tree_add_item (tree, hf_scsi_feature_lun_sn, tvb, offset, additional_length, 0);
                    break;
                default:
		    proto_tree_add_text (tree, tvb, offset, additional_length,
			"SCSI/MMC Unknown Feature:0x%04x",feature);
		    break;
                }
                old_offset+=additional_length;
                len-=4+additional_length;
        }
	END_TRY_SCSI_SHORT_TRANSFER;
    }
}

static void
dissect_mmc4_geteventstatusnotification (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Polled: %u",
                             flags & 0x01);

        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Notification Class Request: %u",
                             flags);

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static const value_string scsi_q_subchannel_adr_val[] = {
    {0x0,	"Q-Subchannel mode info not supplied"},
    {0x1,	"Q-Subchannel encodes current position data"},
    {0x2,	"Q-Subchannel encodes media catalog number"},
    {0x3,	"Q-Subchannel encodes ISRC"},
    {0,NULL}
};
static const value_string scsi_q_subchannel_control_val[] = {
    {0x0,	"2 Audio channels without pre-emphasis (digital copy prohibited)"},
    {0x2,	"2 Audio channels without pre-emphasis (digital copy permitted)"},
    {0x1,	"2 Audio channels with pre-emphasis of 50/15us (digital copy prohibited)"},
    {0x3,	"2 Audio channels with pre-emphasis of 50/15us (digital copy permitted)"},
    {0x8,	"audio channels without pre-emphasis (digital copy prohibited)"},
    {0xa,	"audio channels without pre-emphasis (digital copy permitted)"},
    {0x9,	"2 Audio channels with pre-emphasis of 50/15us (digital copy prohibited)"},
    {0xb,	"2 Audio channels with pre-emphasis of 50/15us (digital copy permitted)"},
    {0x4,	"Data track, recorded uninterrupted (digital copy prohibited)"},
    {0x6,	"Data track, recorded uninterrupted (digital copy permitted)"},
    {0x5,	"Data track, recorded incremental (digital copy prohibited)"},
    {0x7,	"Data track, recorded incremental (digital copy permitted)"},
    {0,NULL}
};

static void
dissect_mmc4_readtocpmaatip (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags, format;
    gint16 len;

    if (tree && isreq && iscdb) {
        format=tvb_get_guint8(tvb, offset+1)&0x0f;
	/* save format so we can decode the response */
        cdata->flags=format;

        switch(format){
        case 0x00:
        case 0x01:
            proto_tree_add_item (tree, hf_scsi_readtoc_time, tvb, offset, 1, 0);
            /* save time so we can pick it up in the response */
            if(tvb_get_guint8(tvb, offset)&0x02){
                cdata->flags|=0x0100;
            }
            break;
        }
        proto_tree_add_item (tree, hf_scsi_readtoc_format, tvb, offset+1, 1, 0);

        switch(format){
        case 0x00:
            proto_tree_add_item (tree, hf_scsi_track, tvb, offset+5, 1, 0);
            /* save track so we can pick it up in the response */
            cdata->flags|=0x0200;
            break;
        case 0x02:
            proto_tree_add_item (tree, hf_scsi_session, tvb, offset+5, 1, 0);
            /* save session so we can pick it up in the response */
            cdata->flags|=0x0400;
            break;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
    if(tree && (!isreq)) {
        len=tvb_get_ntohs(tvb, offset);
        proto_tree_add_item (tree, hf_scsi_data_length, tvb, offset, 2, 0);
        if(cdata->flags&0x0200){
            proto_tree_add_item (tree, hf_scsi_first_track, tvb, offset+2, 1, 0);
            proto_tree_add_item (tree, hf_scsi_readtoc_last_track, tvb, offset+3, 1, 0);
        }
        if(cdata->flags&0x0400){
            proto_tree_add_item (tree, hf_scsi_readtoc_first_session, tvb, offset+2, 1, 0);
            proto_tree_add_item (tree, hf_scsi_readtoc_last_session, tvb, offset+3, 1, 0);
        }
        offset+=4;
        len-=2;
        switch(cdata->flags&0x000f){
        case 0x0:
            while(len>0){
                proto_tree_add_item (tree, hf_scsi_q_subchannel_adr, tvb, offset+1, 1, 0);
                proto_tree_add_item (tree, hf_scsi_q_subchannel_control, tvb, offset+1, 1, 0);
                proto_tree_add_item (tree, hf_scsi_track, tvb, offset+2, 4, 0);
                if(cdata->flags&0x0100){
                    proto_tree_add_item (tree, hf_scsi_track_start_time, tvb, offset+4, 4, 0);
                } else {
                    proto_tree_add_item (tree, hf_scsi_track_start_address, tvb, offset+4, 4, 0);
                }
                offset+=8;
                len-=8;
            }
            break;
        default:
	    proto_tree_add_text (tree, tvb, offset, len,
		"SCSI/MMC Unknown READ TOC Format:0x%04x",cdata->flags&0x000f);
	    break;
        }
    }
}

static void
dissect_mmc4_getperformance (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1, 
                             "Data Type: %u",
                             flags & 0x1f);

        proto_tree_add_text (tree, tvb, offset+1, 4, 
                             "Starting LBA: %u",
                             tvb_get_ntohs (tvb, offset+1));

        proto_tree_add_text (tree, tvb, offset+7, 2, 
                             "Maximum Number of Descriptors: %u",
                             tvb_get_ntohs (tvb, offset+7));

        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1, 
                             "Type: %u",
                             flags);

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
}

static void
dissect_mmc4_synchronizecache (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_synccache_immed, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_synccache_reladr, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_lba, tvb, offset+1, 4, 0);
        proto_tree_add_item (tree, hf_scsi_num_blocks, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
}

static void
dissect_mmc4_readbuffercapacity (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;
    gint16 len;

    if (tree && isreq && iscdb) {
        cdata->flags=0;
        proto_tree_add_item (tree, hf_scsi_rbc_block, tvb, offset, 1, 0);
        if(tvb_get_guint8(tvb, offset)&0x01){
            cdata->flags=1;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
    if(tree && (!isreq)) {
        len=tvb_get_ntohs(tvb, offset);
        proto_tree_add_item (tree, hf_scsi_data_length, tvb, offset, 2, 0);
        if(cdata->flags){
            proto_tree_add_item (tree, hf_scsi_rbc_lob_blocks, tvb, offset+4, 4, 0);
            proto_tree_add_item (tree, hf_scsi_rbc_alob_blocks, tvb, offset+8, 4, 0);
        } else {
            proto_tree_add_item (tree, hf_scsi_rbc_lob_bytes, tvb, offset+4, 4, 0);
            proto_tree_add_item (tree, hf_scsi_rbc_alob_bytes, tvb, offset+8, 4, 0);
        }
    }
}

static void
dissect_mmc4_reservetrack (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_reservation_size, tvb, offset+4, 4, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
}

static const value_string scsi_rti_address_type_val[] = {
    {0x00,	"Logical Block Address"},
    {0x01,	"Logical Track Number"},
    {0x02,	"Session Number"},
    {0,NULL}
};

static void
dissect_mmc4_readtrackinformation (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags, addresstype;

    if (tree && isreq && iscdb) {
        addresstype=tvb_get_guint8(tvb, offset)&0x03;
        proto_tree_add_item (tree, hf_scsi_rti_address_type, tvb, offset+0, 1, 0);
        switch(addresstype){
        case 0x00: /* logical block address */
            proto_tree_add_item (tree, hf_scsi_lba, tvb, offset+1,
                             4, 0);
            break;
        case 0x01: /* logical track number */
            proto_tree_add_item (tree, hf_scsi_track, tvb, offset+1,
                             4, 0);
            break;
        case 0x02: /* logical session number */
            proto_tree_add_item (tree, hf_scsi_session, tvb, offset+1,
                             4, 0);
            break;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
    if(tree && (!isreq)) {
        proto_tree_add_item (tree, hf_scsi_data_length, tvb, 0, 2, 0);
        /* track  offset+2 and offset+32 */
        proto_tree_add_uint (tree, hf_scsi_track, tvb, 2, 1, (tvb_get_guint8(tvb, offset+32)<<8)|tvb_get_guint8(tvb, offset+2));
        /* session  offset+3 and offset+33 */
        proto_tree_add_uint (tree, hf_scsi_session, tvb, 3, 1, (tvb_get_guint8(tvb, offset+33)<<8)|tvb_get_guint8(tvb, offset+3));
        proto_tree_add_item (tree, hf_scsi_rti_damage, tvb, 5, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_copy, tvb, 5, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_track_mode, tvb, 5, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_rt, tvb, 6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_blank, tvb, 6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_packet, tvb, 6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_fp, tvb, 6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_data_mode, tvb, 6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_lra_v, tvb, 7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_rti_nwa_v, tvb, 7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_track_start_address, tvb, offset+8, 4, 0);
        proto_tree_add_item (tree, hf_scsi_next_writable_address, tvb, offset+12, 4, 0);
        proto_tree_add_item (tree, hf_scsi_free_blocks, tvb, offset+16, 4, 0);
        proto_tree_add_item (tree, hf_scsi_fixed_packet_size, tvb, offset+20, 4, 0);
        proto_tree_add_item (tree, hf_scsi_track_size, tvb, offset+24, 4, 0);
        proto_tree_add_item (tree, hf_scsi_last_recorded_address, tvb, offset+28, 4, 0);
        proto_tree_add_item (tree, hf_scsi_read_compatibility_lba, tvb, offset+36, 4, 0);
    }
}

static const value_string scsi_disc_info_sols_val[] = {
    {0x00,	"Empty Session"},
    {0x01,	"Incomplete Session"},
    {0x02,	"Reserved/Damaged Session"},
    {0x03,	"Complete Session"},
    {0,NULL}
};

static const value_string scsi_disc_info_disc_status_val[] = {
    {0x00,	"Empty Disc"},
    {0x01,	"Incomplete Disc"},
    {0x02,	"Finalized Disc"},
    {0x03,	"Others"},
    {0,NULL}
};

static const value_string scsi_disc_info_bgfs_val[] = {
    {0x00,	"Blank or not CD-RW/DVD-RW"},
    {0x01,	"Background Format started but is not running nor complete"},
    {0x02,	"Backgroung Format in progress"},
    {0x03,	"Backgroung Format has completed"},
    {0,NULL}
};

static const value_string scsi_disc_info_disc_type_val[] = {
    {0x00,	"CD-DA or CD-ROM Disc"},
    {0x10,	"CD-I Disc"},
    {0x20,	"CD-ROM XA Disc or DDCD"},
    {0xff,	"Undefined"},
    {0,NULL}
};

static void
dissect_mmc4_readdiscinformation (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);

    }
    if(tree && (!isreq)) {
        proto_tree_add_item (tree, hf_scsi_data_length, tvb, 0, 2, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_erasable, tvb, 2, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_state_of_last_session, tvb, 2, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_disk_status, tvb, 2, 1, 0);
        proto_tree_add_item (tree, hf_scsi_first_track, tvb, offset+3, 1, 0);
        /* number of session  offset+4 and offset+9 */
        proto_tree_add_uint (tree, hf_scsi_disc_info_number_of_sessions, tvb, 4, 1, (tvb_get_guint8(tvb, offset+9)<<8)|tvb_get_guint8(tvb, offset+4));
        /* first track in last session  offset+5 and offset+10 */
        proto_tree_add_uint (tree, hf_scsi_disc_info_first_track_in_last_session, tvb, 5, 1, (tvb_get_guint8(tvb, offset+10)<<8)|tvb_get_guint8(tvb, offset+5));
        /*  last track in last session  offset+6 and offset+11 */
        proto_tree_add_uint (tree, hf_scsi_disc_info_last_track_in_last_session, tvb, 6, 1, (tvb_get_guint8(tvb, offset+11)<<8)|tvb_get_guint8(tvb, offset+6));
        proto_tree_add_item (tree, hf_scsi_disc_info_did_v, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_dbc_v, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_uru, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_dac_v, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_dbit, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_bgfs, tvb, offset+7, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_disc_type, tvb, offset+8, 1, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_disc_identification, tvb, offset+12, 4, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_last_session_lead_in_start_address, tvb, offset+16, 4, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_last_possible_lead_out_start_address, tvb, offset+20, 4, 0);
        proto_tree_add_item (tree, hf_scsi_disc_info_disc_bar_code, tvb, offset+24, 8, 0);
	/* XXX should add OPC table decoding here ... */
    }
}

static void
dissect_mmc4_readdiscstructure (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Sub-Command: %u",
                             flags & 0x0f);

        proto_tree_add_text (tree, tvb, offset+1, 4,
                             "Address: %u",
                             tvb_get_ntohs (tvb, offset+1));

        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "Layer Number: %u",
                             tvb_get_ntohs (tvb, offset+5));

        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "Format Code: %u",
                             tvb_get_ntohs (tvb, offset+6));

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+7, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1,
                             "AGID: %u",
                             flags & 0xc0);

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readcapacity10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;
    guint32 len, block_len, tot_len;
    const char *un;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_readcapacity_flags, tvb,
                                    offset, 1, flags,
                                    "LongLBA = %u, RelAddr = %u",
                                    flags & 0x2, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_readcapacity_lba, tvb, offset+1,
                             4, 0);
        proto_tree_add_item (tree, hf_scsi_readcapacity_pmi, tvb, offset+7,
                             1, 0);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!iscdb) {
        len = tvb_get_ntohl (tvb, offset);
        block_len = tvb_get_ntohl (tvb, offset+4);
        tot_len=((len/1024)*block_len)/1024; /*MB*/
        un="MB";
        if(tot_len>20000){
            tot_len/=1024;
            un="GB";
        }
        proto_tree_add_text (tree, tvb, offset, 4, "LBA: %u (%u %s)",
                             len, tot_len, un);
        proto_tree_add_text (tree, tvb, offset+4, 4, "Block Length: %u bytes",
                             block_len);
    }
}

#define SHORT_FORM_BLOCK_ID        0x00
#define SHORT_FORM_VENDOR_SPECIFIC 0x01
#define LONG_FORM                  0x06
#define EXTENDED_FORM              0x08
#define SERVICE_READ_CAPACITY16	0x10
#define SERVICE_READ_LONG16	0x11

static const value_string service_action_vals[] = {
	{SHORT_FORM_BLOCK_ID,        "Short Form - Block ID"},
	{SHORT_FORM_VENDOR_SPECIFIC, "Short Form - Vendor-Specific"},
	{LONG_FORM,                  "Long Form"},
	{EXTENDED_FORM,              "Extended Form"},
	{SERVICE_READ_CAPACITY16,    "Read Capacity(16)"},
	{SERVICE_READ_LONG16,	     "Read Long(16)"},
	{0, NULL}
};


/* this is either readcapacity16  or  readlong16  depending of what service
   action is set to.   for now we only implement readcapacity16
*/
static void
dissect_sbc2_serviceactionin16 (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, gboolean isreq,
                           gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 service_action, flags;
    guint32 block_len;
    guint64 len, tot_len;
    char *un;

    if (!tree)
        return;

    if (isreq && iscdb) {
        service_action = tvb_get_guint8 (tvb, offset) & 0x1F;
	/* we should store this one for later so the data in can be decoded */
	switch(service_action){
	case SERVICE_READ_CAPACITY16:
        	proto_tree_add_text (tree, tvb, offset, 1,
                             "Service Action: %s",
                             val_to_str (service_action,
                                         service_action_vals,
                                         "Unknown (0x%02x)"));
		offset++;

        	proto_tree_add_text (tree, tvb, offset, 8,
                             "Logical Block Address: %" PRIu64,
                              tvb_get_ntoh64 (tvb, offset));
        	offset += 8;

	        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb, offset, 4, 0);
		offset += 4;

	        proto_tree_add_item (tree, hf_scsi_readcapacity_pmi, tvb, offset, 1, 0);
		offset++;

	        flags = tvb_get_guint8 (tvb, offset);
        	proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
		offset++;

		break;
	};
    } else if (!iscdb) {
	/* assuming for now that all such data in PDUs are read capacity16 */
        len = tvb_get_ntoh64 (tvb, offset);
        block_len = tvb_get_ntohl (tvb, offset+8);
        tot_len=((len/1024)*block_len)/1024; /*MB*/
        un="MB";
        if(tot_len>20000){
            tot_len/=1024;
            un="GB";
        }
        proto_tree_add_text (tree, tvb, offset, 8, "LBA: %" PRIu64 " (%" PRIu64 " %s)",
                             len, tot_len, un);
        proto_tree_add_text (tree, tvb, offset+8, 4, "Block Length: %u bytes",
                             block_len);
    }
}

static void
dissect_sbc2_readdefectdata10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_readdefdata_flags, tvb,
                                    offset, 1, flags, "PLIST = %u, GLIST = %u",
                                    flags & 0x10, flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_cdb_defectfmt, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_readdefectdata12 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_readdefdata_flags, tvb,
                                    offset, 1, flags, "PLIST = %u, GLIST = %u",
                                    flags & 0x10, flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_cdb_defectfmt, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb, offset+5, 4, 0);
        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc2_reassignblocks (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, gboolean isreq,
                           gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);

        proto_tree_add_uint_format (tree, hf_scsi_reassignblks_flags, tvb,
                                    offset, 1, flags,
                                    "LongLBA = %u, LongList = %u",
                                    flags & 0x2, flags & 0x1);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_spc3_senddiagnostic (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb _U_,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree && !isreq)
        return;

    proto_tree_add_uint (tree, hf_scsi_senddiag_st_code, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_pf, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_st, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_devoff, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_unitoff, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_paramlen16, tvb, offset+2, 2, 0);

    flags = tvb_get_guint8 (tvb, offset+4);
    proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                flags,
                                "Vendor Unique = %u, NACA = %u, Link = %u",
                                flags & 0xC0, flags & 0x4, flags & 0x1);
}

static void
dissect_spc3_writebuffer (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb _U_,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree && !isreq)
        return;

    proto_tree_add_uint (tree, hf_scsi_wb_mode, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_wb_bufferid, tvb, offset+1, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_wb_bufoffset, tvb, offset+2, 3, 0);
    proto_tree_add_uint (tree, hf_scsi_paramlen24, tvb, offset+5, 3, 0);

    flags = tvb_get_guint8 (tvb, offset+8);
    proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                flags,
                                "Vendor Unique = %u, NACA = %u, Link = %u",
                                flags & 0xC0, flags & 0x4, flags & 0x1);
}

static void
dissect_scsi_varlencdb (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_control, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_add_cdblen, tvb, offset+6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_svcaction, tvb, offset+7, 2, 0);

    }
}

static void
dissect_ssc2_read6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SILI: %u, FIXED: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_rdwr6_xferlen, tvb, offset+1, 3, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_write6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "FIXED: %u", flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_rdwr6_xferlen, tvb, offset+1, 3,
                             FALSE);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_writefilemarks6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "WSMK: %u, IMMED: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_rdwr6_xferlen, tvb, offset+1, 3,
                             FALSE);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_loadunload (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);

        if (!tree)
            return;

        proto_tree_add_text (tree, tvb, offset, 1,
                             "Immed: %u", tvb_get_guint8 (tvb, offset) & 0x01);
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Hold: %u, EOT: %u, Reten: %u, Load: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_readblocklimits (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags, granularity;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!iscdb) {
    	granularity = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1, "Granularity: %u (%u %s)",
                             granularity, 1 << granularity,
                             plurality(1 << granularity, "byte", "bytes"));
        proto_tree_add_text (tree, tvb, offset+1, 3, "Maximum Block Length Limit: %u bytes",
                             tvb_get_ntoh24 (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+4, 2, "Minimum Block Length Limit: %u bytes",
                             tvb_get_ntohs (tvb, offset+4));
    }
}

#define BCU  0x20
#define BYCU 0x10
#define MPU  0x08
#define BPU  0x04

static void
dissect_ssc2_readposition (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata)
{
    gint service_action;
    guint8 flags;

    if (!tree)
        return;

    if (isreq && iscdb) {
        service_action = tvb_get_guint8 (tvb, offset) & 0x1F;
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Service Action: %s",
                             val_to_str (service_action,
                                         service_action_vals,
                                         "Unknown (0x%02x)"));
        /* Remember the service action so we can decode the reply */
        if (cdata != NULL) {
            cdata->flags = service_action;
        }
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Parameter Len: %u",
                             tvb_get_ntohs (tvb, offset+6));
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq) {
        if (cdata)
            service_action = cdata->flags;
        else
            service_action = -1; /* unknown */
        switch (service_action) {
        case SHORT_FORM_BLOCK_ID:
        case SHORT_FORM_VENDOR_SPECIFIC:
            flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                             "BOP: %u, EOP: %u, BCU: %u, BYCU: %u, BPU: %u, PERR: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & BCU) >> 5, (flags & BYCU) >> 4,
                             (flags & BPU) >> 2, (flags & 0x02) >> 1);
            offset += 1;

            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Partition Number: %u",
                                 tvb_get_guint8 (tvb, offset));
            offset += 1;

            offset += 2; /* reserved */

            if (!(flags & BPU)) {
                proto_tree_add_text (tree, tvb, offset, 4,
                                     "First Block Location: %u",
                                     tvb_get_ntohl (tvb, offset));
                offset += 4;

                proto_tree_add_text (tree, tvb, offset, 4,
                                     "Last Block Location: %u",
                                     tvb_get_ntohl (tvb, offset));
                offset += 4;
            } else
                offset += 8;

            offset += 1; /* reserved */

            if (!(flags & BCU)) {
                proto_tree_add_text (tree, tvb, offset, 3,
                                     "Number of Blocks in Buffer: %u",
                                     tvb_get_ntoh24 (tvb, offset));
            }
            offset += 3;

            if (!(flags & BYCU)) {
                proto_tree_add_text (tree, tvb, offset, 4,
                                     "Number of Bytes in Buffer: %u",
                                     tvb_get_ntohl (tvb, offset));
            }
            offset += 4;
            break;

        case LONG_FORM:
            flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                             "BOP: %u, EOP: %u, MPU: %u, BPU: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & MPU) >> 3, (flags & BPU) >> 2);
            offset += 1;

            offset += 3; /* reserved */

            if (!(flags & BPU)) {
                proto_tree_add_text (tree, tvb, offset, 4,
                                     "Partition Number: %u",
                                     tvb_get_ntohl (tvb, offset));
                offset += 4;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Block Number: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                 offset += 8;
            } else
                offset += 12;

            if (!(flags & MPU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "File Number: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Set Number: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;
            } else
                offset += 16;
            break;

        case EXTENDED_FORM:
            flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                             "BOP: %u, EOP: %u, BCU: %u, BYCU: %u, MPU: %u, BPU: %u, PERR: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6,
                             (flags & BCU) >> 5, (flags & BYCU) >> 4,
                             (flags & MPU) >> 3, (flags & BPU) >> 2,
                             (flags & 0x02) >> 1);
            offset += 1;

            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Partition Number: %u",
                                 tvb_get_guint8 (tvb, offset));
            offset += 1;

            proto_tree_add_text (tree, tvb, offset, 2,
                                 "Additional Length: %u",
                                 tvb_get_ntohs (tvb, offset));
            offset += 2;

            offset += 1; /* reserved */

            if (!(flags & BCU)) {
                proto_tree_add_text (tree, tvb, offset, 3,
                                     "Number of Blocks in Buffer: %u",
                                     tvb_get_ntoh24 (tvb, offset));
            }
            offset += 3;

            if (!(flags & BPU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "First Block Location: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Last Block Location: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;
            } else
                offset += 16;

            offset += 1; /* reserved */

            if (!(flags & BYCU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Number of Bytes in Buffer: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
            }
            offset += 8;
            break;

        default:
            break;
        }
    }
}


static void
dissect_ssc2_rewind (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);

        if (!tree)
            return;

        proto_tree_add_text (tree, tvb, offset, 1,
                             "Immed: %u", tvb_get_guint8 (tvb, offset) & 0x01);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_locate10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "BT: %u, CP: %u, IMMED: %u",
                             (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_item (tree, hf_ssc3_locate10_loid, tvb, offset+2, 4, 0);

        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "Partition: %u",
                            flags);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_locate16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "DEST_TYPE: %u, CP: %u, IMMED: %u",
                             (flags & 0x18) >> 3,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Partition: %u",
                            flags);

        proto_tree_add_item (tree, hf_ssc3_locate16_loid, tvb, offset+3, 8, 0);

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_erase6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "IMMED: %u, LONG: %u",
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_erase16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "FCS: %u, LCS: %u, IMMED: %u, LONG: %u",
                             (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Partition: %u", tvb_get_guint8(tvb,offset+2));

        proto_tree_add_text (tree, tvb, offset+3, 8,
                             "Logical Object Identifier: 0x%02x%02x%02x%02x%02x%02x%02x%02x",
                             tvb_get_guint8(tvb,offset+3),
                             tvb_get_guint8(tvb,offset+4),
                             tvb_get_guint8(tvb,offset+5),
                             tvb_get_guint8(tvb,offset+6),
                             tvb_get_guint8(tvb,offset+7),
                             tvb_get_guint8(tvb,offset+8),
                             tvb_get_guint8(tvb,offset+9),
                             tvb_get_guint8(tvb,offset+10));

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_space6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "CODE: %u",
                             flags & 0x0f);

        proto_tree_add_item (tree, hf_ssc3_space6_count, tvb, offset+1, 3, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_space16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "CODE: %u",
                             flags & 0x0f);

        proto_tree_add_item (tree, hf_ssc3_space16_count, tvb, offset+3, 8, 0);

        proto_tree_add_text (tree, tvb, offset+11, 2,
                             "Parameter Len: %u",
                             tvb_get_ntohs (tvb, offset+11));

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_formatmedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "VERIFY: %u, IMMED: %u",
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_text (tree, tvb, offset+1, 1,
                             "Format: 0x%02x", tvb_get_guint8(tvb,offset+1)&0x0f);

        proto_tree_add_item (tree, hf_scsi_rdwr10_xferlen, tvb, offset+2, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_smc2_movemedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_text (tree, tvb, offset+1, 2,
                             "Medium Transport Address: %u",
                             tvb_get_ntohs (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+3, 2,
                             "Source Address: %u",
                             tvb_get_ntohs (tvb, offset+3));
        proto_tree_add_text (tree, tvb, offset+5, 2,
                             "Destination Address: %u",
                             tvb_get_ntohs (tvb, offset+5));
        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1,
                             "INV: %u", flags & 0x01);
        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

#define MT_ELEM  0x1
#define ST_ELEM  0x2
#define I_E_ELEM 0x3
#define DT_ELEM  0x4

static const value_string element_type_code_vals[] = {
    {0x0,      "All element types"},
    {MT_ELEM,  "Medium transport element"},
    {ST_ELEM,  "Storage element"},
    {I_E_ELEM, "Import/export element"},
    {DT_ELEM,  "Data transfer element"},
    {0, NULL}
};

#define PVOLTAG 0x80
#define AVOLTAG 0x40

#define EXCEPT 0x04

#define ID_VALID 0x20
#define LU_VALID 0x10

#define SVALID 0x80

static void
dissect_scsi_smc2_volume_tag (tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, guint offset,
                              const char *name)
{
    char volid[32+1];
    char *p;

    tvb_memcpy (tvb, (guint8 *)volid, offset, 32);
    p = &volid[32];
    for (;;) {
    	*p = '\0';
        if (p == volid)
            break;
        if (*(p - 1) != ' ')
            break;
        p--;
    }
    proto_tree_add_text (tree, tvb, offset, 36,
                         "%s: Volume Identification = \"%s\", Volume Sequence Number = %u",
	                 name, volid, tvb_get_ntohs (tvb, offset+34));
}

static void
dissect_scsi_smc2_element (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset,
                         guint elem_bytecnt, guint8 elem_type,
                         guint8 voltag_flags)
{
    guint8 flags;
    guint8 ident_len;

    if (elem_bytecnt < 2)
        return;
    proto_tree_add_text (tree, tvb, offset, 2,
                         "Element Address: %u",
                         tvb_get_ntohs (tvb, offset));
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    switch (elem_type) {

    case MT_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                            "EXCEPT: %u, FULL: %u",
                             (flags & EXCEPT) >> 2, flags & 0x01);
        break;

    case ST_ELEM:
    case DT_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                             "ACCESS: %u, EXCEPT: %u, FULL: %u",
                             (flags & 0x08) >> 3,
                             (flags & EXCEPT) >> 2, flags & 0x01);
        break;

    case I_E_ELEM:
        proto_tree_add_text (tree, tvb, offset, 1,
                             "cmc: %u, INENAB: %u, EXENAB: %u, ACCESS: %u, EXCEPT: %u, IMPEXP: %u, FULL: %u",
                             (flags & 0x40) >> 6,
                             (flags & 0x20) >> 5,
                             (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3,
                             (flags & EXCEPT) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);
        break;
    }
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    offset += 1; /* reserved */
    elem_bytecnt -= 1;

    if (elem_bytecnt < 2)
        return;
    if (flags & EXCEPT) {
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Additional Sense Code+Qualifier: %s",
                             val_to_str (tvb_get_ntohs (tvb, offset),
                                         scsi_asc_val, "Unknown (0x%04x)"));
    }
    offset += 2;
    elem_bytecnt -= 2;

    if (elem_bytecnt < 3)
        return;
    switch (elem_type) {

    case DT_ELEM:
        flags = tvb_get_guint8 (tvb, offset);
        if (flags & LU_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "NOT BUS: %u, ID VALID: %u, LU VALID: 1, LUN: %u",
                                 (flags & 0x80) >> 7,
                                 (flags & ID_VALID) >> 5,
                                 flags & 0x07);
        } else if (flags & ID_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "ID VALID: 1, LU VALID: 0");
        } else {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "ID VALID: 0, LU VALID: 0");
        }
        offset += 1;
        if (flags & ID_VALID) {
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "SCSI Bus Address: %u",
                                 tvb_get_guint8 (tvb, offset));
        }
        offset += 1;
        offset += 1; /* reserved */
        break;

    default:
        offset += 3; /* reserved */
        break;
    }
    elem_bytecnt -= 3;

    if (elem_bytecnt < 3)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    if (flags & SVALID) {
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SVALID: 1, INVERT: %u",
                             (flags & 0x40) >> 6);
        offset += 1;
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Source Storage Element Address: %u",
                             tvb_get_ntohs (tvb, offset));
        offset += 2;
    } else {
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SVALID: 0");
        offset += 3;
    }
    elem_bytecnt -= 3;

    if (voltag_flags & PVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc2_volume_tag (tvb, pinfo, tree, offset,
                                      "Primary Volume Tag Information");
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (voltag_flags & AVOLTAG) {
        if (elem_bytecnt < 36)
            return;
        dissect_scsi_smc2_volume_tag (tvb, pinfo, tree, offset,
                                      "Alternate Volume Tag Information");
        offset += 36;
        elem_bytecnt -= 36;
    }

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Code Set: %s",
                         val_to_str (flags & 0x0F,
                                     scsi_devid_codeset_val,
                                     "Unknown (0x%02x)"));
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    flags = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Identifier Type: %s",
                         val_to_str ((flags & 0x0F),
                                     scsi_devid_idtype_val,
                                     "Unknown (0x%02x)"));
    offset += 1;
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    offset += 1; /* reserved */
    elem_bytecnt -= 1;

    if (elem_bytecnt < 1)
        return;
    ident_len = tvb_get_guint8 (tvb, offset);
    proto_tree_add_text (tree, tvb, offset, 1,
                         "Identifier Length: %u",
                         ident_len);
    offset += 1;
    elem_bytecnt -= 1;

    if (ident_len != 0) {
        if (elem_bytecnt < ident_len)
            return;
        proto_tree_add_text (tree, tvb, offset, ident_len,
                             "Identifier: %s",
                             tvb_bytes_to_str (tvb, offset, ident_len));
        offset += ident_len;
        elem_bytecnt -= ident_len;
    }
    if (elem_bytecnt != 0) {
        proto_tree_add_text (tree, tvb, offset, elem_bytecnt,
                             "Vendor-specific Data: %s",
                             tvb_bytes_to_str (tvb, offset, elem_bytecnt));
    }
}

static void
dissect_scsi_smc2_elements (tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, guint offset,
                            guint desc_bytecnt, guint8 elem_type,
                            guint8 voltag_flags, guint16 elem_desc_len)
{
    guint elem_bytecnt;

    while (desc_bytecnt != 0) {
        elem_bytecnt = elem_desc_len;
        if (elem_bytecnt > desc_bytecnt)
            elem_bytecnt = desc_bytecnt;
        dissect_scsi_smc2_element (tvb, pinfo, tree, offset, elem_bytecnt,
                                   elem_type, voltag_flags);
        offset += elem_bytecnt;
        desc_bytecnt -= elem_bytecnt;
    }
}

static void
dissect_smc2_readelementstatus (tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;
    guint numelem, bytecnt, desc_bytecnt;
    guint8 elem_type;
    guint8 voltag_flags;
    guint16 elem_desc_len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "VOLTAG: %u, Element Type Code: %s",
                             (flags & 0x10) >> 4,
                             val_to_str (flags & 0xF, element_type_code_vals,
                                         "Unknown (0x%x)"));
        proto_tree_add_text (tree, tvb, offset+1, 2,
                             "Starting Element Address: %u",
                             tvb_get_ntohs (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+3, 2,
                             "Number of Elements: %u",
                             tvb_get_ntohs (tvb, offset+3));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "CURDATA: %u, DVCID: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_text (tree, tvb, offset+6, 3,
                             "Allocation Length: %u",
                             tvb_get_ntoh24 (tvb, offset+6));
        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq) {
        proto_tree_add_text (tree, tvb, offset, 2,
                             "First Element Address Reported: %u",
                             tvb_get_ntohs (tvb, offset));
        offset += 2;
        numelem = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2,
                             "Number of Elements Available: %u", numelem);
        offset += 2;
        offset += 1; /* reserved */
        bytecnt = tvb_get_ntoh24 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 3,
                             "Byte Count of Report Available: %u", bytecnt);
        offset += 3;
        while (bytecnt != 0) {
            if (bytecnt < 1)
                break;
            elem_type = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Element Type Code: %s",
                                 val_to_str (elem_type, element_type_code_vals,
                                             "Unknown (0x%x)"));
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 1)
                break;
            voltag_flags = tvb_get_guint8 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 1,
                                 "PVOLTAG: %u, AVOLTAG: %u",
                                 (voltag_flags & PVOLTAG) >> 7,
                                 (voltag_flags & AVOLTAG) >> 6);
            offset += 1;
            bytecnt -= 1;

            if (bytecnt < 2)
                break;
            elem_desc_len = tvb_get_ntohs (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 2,
                                 "Element Descriptor Length: %u",
                                 elem_desc_len);
            offset += 2;
            bytecnt -= 2;

            if (bytecnt < 1)
                break;
            offset += 1; /* reserved */
            bytecnt -= 1;

            if (bytecnt < 3)
                break;
            desc_bytecnt = tvb_get_ntoh24 (tvb, offset);
            proto_tree_add_text (tree, tvb, offset, 3,
                                 "Byte Count Of Descriptor Data Available: %u",
                                 desc_bytecnt);
            offset += 3;
            bytecnt -= 3;

            if (desc_bytecnt > bytecnt)
                desc_bytecnt = bytecnt;
            dissect_scsi_smc2_elements (tvb, pinfo, tree, offset,
                                        desc_bytecnt, elem_type,
                                        voltag_flags, elem_desc_len);
            offset += desc_bytecnt;
            bytecnt -= desc_bytecnt;
        }
    }
}

void
dissect_scsi_rsp (tvbuff_t *tvb, packet_info *pinfo _U_,
                  proto_tree *tree, guint16 lun, guint8 scsi_status)
{
    proto_item *ti;
    proto_tree *scsi_tree = NULL;

    /* Nothing really to do here, just print some stuff passed to us
     * and blow up the data structures for this SCSI task.
     */
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, 0,
                                             0, "SCSI Response");
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);

	ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, lun);
	PROTO_ITEM_SET_GENERATED(ti);
	ti=proto_tree_add_uint(scsi_tree, hf_scsi_status, tvb, 0, 0, scsi_status);
	PROTO_ITEM_SET_GENERATED(ti);
    }
    if (check_col (pinfo->cinfo, COL_INFO)) {
         col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI: Response LUN: 0x%02x (%s)", lun, val_to_str(scsi_status, scsi_status_val, "Unknown (0x%08x)"));
     }

}

void
dissect_scsi_snsinfo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, guint snslen, guint16 lun)
{
    proto_item *ti;
    proto_tree *sns_tree=NULL;
    char *old_proto;

    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    scsi_end_task (pinfo);

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                             snslen, "SCSI: SNS Info");
        sns_tree = proto_item_add_subtree (ti, ett_scsi);
    }


    ti=proto_tree_add_uint(sns_tree, hf_scsi_lun, tvb, 0, 0, lun);
    PROTO_ITEM_SET_GENERATED(ti);
    if (check_col (pinfo->cinfo, COL_INFO)) {
         col_append_fstr (pinfo->cinfo, COL_INFO, " LUN:0x%02x ", lun);
    }

    dissect_scsi_fix_snsinfo (tvb, sns_tree, offset);

    pinfo->current_proto=old_proto;
}


/* list of commands for each commandset */
typedef void (*scsi_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, guint offset,
		gboolean isreq, gboolean iscdb,
                guint32 payload_len, scsi_task_data_t *cdata);

typedef struct _scsi_cdb_table_t {
	scsi_dissector_t	func;
} scsi_cdb_table_t;

static scsi_cdb_table_t spc[256] = {
/*SPC 0x00*/{dissect_spc3_testunitready},
/*SPC 0x01*/{NULL},
/*SPC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc3_requestsense},
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
/*SPC 0x12*/{dissect_spc3_inquiry},
/*SPC 0x13*/{NULL},
/*SPC 0x14*/{NULL},
/*SPC 0x15*/{dissect_spc3_modeselect6},
/*SPC 0x16*/{dissect_spc2_reserve6},
/*SPC 0x17*/{dissect_spc2_release6},
/*SPC 0x18*/{NULL},
/*SPC 0x19*/{NULL},
/*SPC 0x1a*/{dissect_spc3_modesense6},
/*SPC 0x1b*/{NULL},
/*SPC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc3_senddiagnostic},
/*SPC 0x1e*/{dissect_spc3_preventallowmediaremoval},
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
/*SPC 0x3b*/{dissect_spc3_writebuffer},
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
/*SPC 0x4c*/{dissect_spc3_logselect},
/*SPC 0x4d*/{dissect_spc3_logsense},
/*SPC 0x4e*/{NULL},
/*SPC 0x4f*/{NULL},
/*SPC 0x50*/{NULL},
/*SPC 0x51*/{NULL},
/*SPC 0x52*/{NULL},
/*SPC 0x53*/{NULL},
/*SPC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc3_modeselect10},
/*SPC 0x56*/{dissect_spc2_reserve10},
/*SPC 0x57*/{dissect_spc2_release10},
/*SPC 0x58*/{NULL},
/*SPC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc3_modesense10},
/*SPC 0x5b*/{NULL},
/*SPC 0x5c*/{NULL},
/*SPC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc3_persistentreservein},
/*SPC 0x5f*/{dissect_spc3_persistentreserveout},
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
/*SPC 0x83*/{dissect_spc3_extcopy},
/*SPC 0x84*/{NULL},
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
/*SPC 0xa0*/{dissect_spc3_reportluns},
/*SPC 0xa1*/{NULL},
/*SPC 0xa2*/{NULL},
/*SPC 0xa3*/{dissect_spc3_reportdeviceidentifier},
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

static scsi_cdb_table_t sbc[256] = {
/*SBC 0x00*/{NULL},
/*SBC 0x01*/{NULL},
/*SBC 0x02*/{NULL},
/*SBC 0x03*/{NULL},
/*SBC 0x04*/{dissect_sbc2_formatunit},
/*SBC 0x05*/{NULL},
/*SBC 0x06*/{NULL},
/*SBC 0x07*/{dissect_sbc2_reassignblocks},
/*SBC 0x08*/{dissect_sbc2_readwrite6},
/*SBC 0x09*/{NULL},
/*SBC 0x0a*/{dissect_sbc2_readwrite6},
/*SBC 0x0b*/{NULL},
/*SBC 0x0c*/{NULL},
/*SBC 0x0d*/{NULL},
/*SBC 0x0e*/{NULL},
/*SBC 0x0f*/{NULL},
/*SBC 0x10*/{NULL},
/*SBC 0x11*/{NULL},
/*SBC 0x12*/{NULL},
/*SBC 0x13*/{NULL},
/*SBC 0x14*/{NULL},
/*SBC 0x15*/{NULL},
/*SBC 0x16*/{NULL},
/*SBC 0x17*/{NULL},
/*SBC 0x18*/{NULL},
/*SBC 0x19*/{NULL},
/*SBC 0x1a*/{NULL},
/*SBC 0x1b*/{dissect_sbc2_startstopunit},
/*SBC 0x1c*/{NULL},
/*SBC 0x1d*/{NULL},
/*SBC 0x1e*/{dissect_spc3_preventallowmediaremoval},
/*SBC 0x1f*/{NULL},
/*SBC 0x20*/{NULL},
/*SBC 0x21*/{NULL},
/*SBC 0x22*/{NULL},
/*SBC 0x23*/{NULL},
/*SBC 0x24*/{NULL},
/*SBC 0x25*/{dissect_sbc2_readcapacity10},
/*SBC 0x26*/{NULL},
/*SBC 0x27*/{NULL},
/*SBC 0x28*/{dissect_sbc2_readwrite10},
/*SBC 0x29*/{NULL},
/*SBC 0x2a*/{dissect_sbc2_readwrite10},
/*SBC 0x2b*/{NULL},
/*SBC 0x2c*/{NULL},
/*SBC 0x2d*/{NULL},
/*SBC 0x2e*/{dissect_sbc2_wrverify10},
/*SBC 0x2f*/{dissect_sbc2_verify10},
/*SBC 0x30*/{NULL},
/*SBC 0x31*/{NULL},
/*SBC 0x32*/{NULL},
/*SBC 0x33*/{NULL},
/*SBC 0x34*/{NULL},
/*SBC 0x35*/{NULL},
/*SBC 0x36*/{NULL},
/*SBC 0x37*/{dissect_sbc2_readdefectdata10},
/*SBC 0x38*/{NULL},
/*SBC 0x39*/{NULL},
/*SBC 0x3a*/{NULL},
/*SBC 0x3b*/{NULL},
/*SBC 0x3c*/{NULL},
/*SBC 0x3d*/{NULL},
/*SBC 0x3e*/{NULL},
/*SBC 0x3f*/{NULL},
/*SBC 0x40*/{NULL},
/*SBC 0x41*/{NULL},
/*SBC 0x42*/{NULL},
/*SBC 0x43*/{NULL},
/*SBC 0x44*/{NULL},
/*SBC 0x45*/{NULL},
/*SBC 0x46*/{NULL},
/*SBC 0x47*/{NULL},
/*SBC 0x48*/{NULL},
/*SBC 0x49*/{NULL},
/*SBC 0x4a*/{NULL},
/*SBC 0x4b*/{NULL},
/*SBC 0x4c*/{NULL},
/*SBC 0x4d*/{NULL},
/*SBC 0x4e*/{NULL},
/*SBC 0x4f*/{NULL},
/*SBC 0x50*/{NULL},
/*SBC 0x51*/{NULL},
/*SBC 0x52*/{NULL},
/*SBC 0x53*/{NULL},
/*SBC 0x54*/{NULL},
/*SBC 0x55*/{NULL},
/*SBC 0x56*/{NULL},
/*SBC 0x57*/{NULL},
/*SBC 0x58*/{NULL},
/*SBC 0x59*/{NULL},
/*SBC 0x5a*/{NULL},
/*SBC 0x5b*/{NULL},
/*SBC 0x5c*/{NULL},
/*SBC 0x5d*/{NULL},
/*SBC 0x5e*/{NULL},
/*SBC 0x5f*/{NULL},
/*SBC 0x60*/{NULL},
/*SBC 0x61*/{NULL},
/*SBC 0x62*/{NULL},
/*SBC 0x63*/{NULL},
/*SBC 0x64*/{NULL},
/*SBC 0x65*/{NULL},
/*SBC 0x66*/{NULL},
/*SBC 0x67*/{NULL},
/*SBC 0x68*/{NULL},
/*SBC 0x69*/{NULL},
/*SBC 0x6a*/{NULL},
/*SBC 0x6b*/{NULL},
/*SBC 0x6c*/{NULL},
/*SBC 0x6d*/{NULL},
/*SBC 0x6e*/{NULL},
/*SBC 0x6f*/{NULL},
/*SBC 0x70*/{NULL},
/*SBC 0x71*/{NULL},
/*SBC 0x72*/{NULL},
/*SBC 0x73*/{NULL},
/*SBC 0x74*/{NULL},
/*SBC 0x75*/{NULL},
/*SBC 0x76*/{NULL},
/*SBC 0x77*/{NULL},
/*SBC 0x78*/{NULL},
/*SBC 0x79*/{NULL},
/*SBC 0x7a*/{NULL},
/*SBC 0x7b*/{NULL},
/*SBC 0x7c*/{NULL},
/*SBC 0x7d*/{NULL},
/*SBC 0x7e*/{NULL},
/*SBC 0x7f*/{NULL},
/*SBC 0x80*/{NULL},
/*SBC 0x81*/{NULL},
/*SBC 0x82*/{NULL},
/*SBC 0x83*/{NULL},
/*SBC 0x84*/{NULL},
/*SBC 0x85*/{NULL},
/*SBC 0x86*/{NULL},
/*SBC 0x87*/{NULL},
/*SBC 0x88*/{dissect_sbc2_readwrite16},
/*SBC 0x89*/{NULL},
/*SBC 0x8a*/{dissect_sbc2_readwrite16},
/*SBC 0x8b*/{NULL},
/*SBC 0x8c*/{NULL},
/*SBC 0x8d*/{NULL},
/*SBC 0x8e*/{dissect_sbc2_wrverify16},
/*SBC 0x8f*/{dissect_sbc2_verify16},
/*SBC 0x90*/{NULL},
/*SBC 0x91*/{NULL},
/*SBC 0x92*/{NULL},
/*SBC 0x93*/{NULL},
/*SBC 0x94*/{NULL},
/*SBC 0x95*/{NULL},
/*SBC 0x96*/{NULL},
/*SBC 0x97*/{NULL},
/*SBC 0x98*/{NULL},
/*SBC 0x99*/{NULL},
/*SBC 0x9a*/{NULL},
/*SBC 0x9b*/{NULL},
/*SBC 0x9c*/{NULL},
/*SBC 0x9d*/{NULL},
/*SBC 0x9e*/{dissect_sbc2_serviceactionin16},
/*SBC 0x9f*/{NULL},
/*SBC 0xa0*/{NULL},
/*SBC 0xa1*/{NULL},
/*SBC 0xa2*/{NULL},
/*SBC 0xa3*/{NULL},
/*SBC 0xa4*/{NULL},
/*SBC 0xa5*/{NULL},
/*SBC 0xa6*/{NULL},
/*SBC 0xa7*/{NULL},
/*SBC 0xa8*/{dissect_sbc2_readwrite12},
/*SBC 0xa9*/{NULL},
/*SBC 0xaa*/{dissect_sbc2_readwrite12},
/*SBC 0xab*/{NULL},
/*SBC 0xac*/{NULL},
/*SBC 0xad*/{NULL},
/*SBC 0xae*/{dissect_sbc2_wrverify12},
/*SBC 0xaf*/{dissect_sbc2_verify12},
/*SBC 0xb0*/{NULL},
/*SBC 0xb1*/{NULL},
/*SBC 0xb2*/{NULL},
/*SBC 0xb3*/{NULL},
/*SBC 0xb4*/{NULL},
/*SBC 0xb5*/{NULL},
/*SBC 0xb6*/{NULL},
/*SBC 0xb7*/{dissect_sbc2_readdefectdata12},
/*SBC 0xb8*/{NULL},
/*SBC 0xb9*/{NULL},
/*SBC 0xba*/{NULL},
/*SBC 0xbb*/{NULL},
/*SBC 0xbc*/{NULL},
/*SBC 0xbd*/{NULL},
/*SBC 0xbe*/{NULL},
/*SBC 0xbf*/{NULL},
/*SBC 0xc0*/{NULL},
/*SBC 0xc1*/{NULL},
/*SBC 0xc2*/{NULL},
/*SBC 0xc3*/{NULL},
/*SBC 0xc4*/{NULL},
/*SBC 0xc5*/{NULL},
/*SBC 0xc6*/{NULL},
/*SBC 0xc7*/{NULL},
/*SBC 0xc8*/{NULL},
/*SBC 0xc9*/{NULL},
/*SBC 0xca*/{NULL},
/*SBC 0xcb*/{NULL},
/*SBC 0xcc*/{NULL},
/*SBC 0xcd*/{NULL},
/*SBC 0xce*/{NULL},
/*SBC 0xcf*/{NULL},
/*SBC 0xd0*/{NULL},
/*SBC 0xd1*/{NULL},
/*SBC 0xd2*/{NULL},
/*SBC 0xd3*/{NULL},
/*SBC 0xd4*/{NULL},
/*SBC 0xd5*/{NULL},
/*SBC 0xd6*/{NULL},
/*SBC 0xd7*/{NULL},
/*SBC 0xd8*/{NULL},
/*SBC 0xd9*/{NULL},
/*SBC 0xda*/{NULL},
/*SBC 0xdb*/{NULL},
/*SBC 0xdc*/{NULL},
/*SBC 0xdd*/{NULL},
/*SBC 0xde*/{NULL},
/*SBC 0xdf*/{NULL},
/*SBC 0xe0*/{NULL},
/*SBC 0xe1*/{NULL},
/*SBC 0xe2*/{NULL},
/*SBC 0xe3*/{NULL},
/*SBC 0xe4*/{NULL},
/*SBC 0xe5*/{NULL},
/*SBC 0xe6*/{NULL},
/*SBC 0xe7*/{NULL},
/*SBC 0xe8*/{NULL},
/*SBC 0xe9*/{NULL},
/*SBC 0xea*/{NULL},
/*SBC 0xeb*/{NULL},
/*SBC 0xec*/{NULL},
/*SBC 0xed*/{NULL},
/*SBC 0xee*/{NULL},
/*SBC 0xef*/{NULL},
/*SBC 0xf0*/{NULL},
/*SBC 0xf1*/{NULL},
/*SBC 0xf2*/{NULL},
/*SBC 0xf3*/{NULL},
/*SBC 0xf4*/{NULL},
/*SBC 0xf5*/{NULL},
/*SBC 0xf6*/{NULL},
/*SBC 0xf7*/{NULL},
/*SBC 0xf8*/{NULL},
/*SBC 0xf9*/{NULL},
/*SBC 0xfa*/{NULL},
/*SBC 0xfb*/{NULL},
/*SBC 0xfc*/{NULL},
/*SBC 0xfd*/{NULL},
/*SBC 0xfe*/{NULL},
/*SBC 0xff*/{NULL}
};

static scsi_cdb_table_t ssc[256] = {
/*SSC 0x00*/{NULL},
/*SSC 0x01*/{dissect_ssc2_rewind},
/*SSC 0x02*/{NULL},
/*SSC 0x03*/{NULL},
/*SSC 0x04*/{dissect_ssc2_formatmedium},
/*SSC 0x05*/{dissect_ssc2_readblocklimits},
/*SSC 0x06*/{NULL},
/*SSC 0x07*/{NULL},
/*SSC 0x08*/{dissect_ssc2_read6},
/*SSC 0x09*/{NULL},
/*SSC 0x0a*/{dissect_ssc2_write6},
/*SSC 0x0b*/{NULL},
/*SSC 0x0c*/{NULL},
/*SSC 0x0d*/{NULL},
/*SSC 0x0e*/{NULL},
/*SSC 0x0f*/{NULL},
/*SSC 0x10*/{dissect_ssc2_writefilemarks6},
/*SSC 0x11*/{dissect_ssc2_space6},
/*SSC 0x12*/{NULL},
/*SSC 0x13*/{NULL},
/*SSC 0x14*/{NULL},
/*SSC 0x15*/{NULL},
/*SSC 0x16*/{NULL},
/*SSC 0x17*/{NULL},
/*SSC 0x18*/{NULL},
/*SSC 0x19*/{dissect_ssc2_erase6},
/*SSC 0x1a*/{NULL},
/*SSC 0x1b*/{dissect_ssc2_loadunload},
/*SSC 0x1c*/{NULL},
/*SSC 0x1d*/{NULL},
/*SSC 0x1e*/{dissect_spc3_preventallowmediaremoval},
/*SSC 0x1f*/{NULL},
/*SSC 0x20*/{NULL},
/*SSC 0x21*/{NULL},
/*SSC 0x22*/{NULL},
/*SSC 0x23*/{NULL},
/*SSC 0x24*/{NULL},
/*SSC 0x25*/{NULL},
/*SSC 0x26*/{NULL},
/*SSC 0x27*/{NULL},
/*SSC 0x28*/{NULL},
/*SSC 0x29*/{NULL},
/*SSC 0x2a*/{NULL},
/*SSC 0x2b*/{dissect_ssc2_locate10},
/*SSC 0x2c*/{NULL},
/*SSC 0x2d*/{NULL},
/*SSC 0x2e*/{NULL},
/*SSC 0x2f*/{NULL},
/*SSC 0x30*/{NULL},
/*SSC 0x31*/{NULL},
/*SSC 0x32*/{NULL},
/*SSC 0x33*/{NULL},
/*SSC 0x34*/{dissect_ssc2_readposition},
/*SSC 0x35*/{NULL},
/*SSC 0x36*/{NULL},
/*SSC 0x37*/{NULL},
/*SSC 0x38*/{NULL},
/*SSC 0x39*/{NULL},
/*SSC 0x3a*/{NULL},
/*SSC 0x3b*/{NULL},
/*SSC 0x3c*/{NULL},
/*SSC 0x3d*/{NULL},
/*SSC 0x3e*/{NULL},
/*SSC 0x3f*/{NULL},
/*SSC 0x40*/{NULL},
/*SSC 0x41*/{NULL},
/*SSC 0x42*/{NULL},
/*SSC 0x43*/{NULL},
/*SSC 0x44*/{NULL},
/*SSC 0x45*/{NULL},
/*SSC 0x46*/{NULL},
/*SSC 0x47*/{NULL},
/*SSC 0x48*/{NULL},
/*SSC 0x49*/{NULL},
/*SSC 0x4a*/{NULL},
/*SSC 0x4b*/{NULL},
/*SSC 0x4c*/{NULL},
/*SSC 0x4d*/{NULL},
/*SSC 0x4e*/{NULL},
/*SSC 0x4f*/{NULL},
/*SSC 0x50*/{NULL},
/*SSC 0x51*/{NULL},
/*SSC 0x52*/{NULL},
/*SSC 0x53*/{NULL},
/*SSC 0x54*/{NULL},
/*SSC 0x55*/{NULL},
/*SSC 0x56*/{NULL},
/*SSC 0x57*/{NULL},
/*SSC 0x58*/{NULL},
/*SSC 0x59*/{NULL},
/*SSC 0x5a*/{NULL},
/*SSC 0x5b*/{NULL},
/*SSC 0x5c*/{NULL},
/*SSC 0x5d*/{NULL},
/*SSC 0x5e*/{NULL},
/*SSC 0x5f*/{NULL},
/*SSC 0x60*/{NULL},
/*SSC 0x61*/{NULL},
/*SSC 0x62*/{NULL},
/*SSC 0x63*/{NULL},
/*SSC 0x64*/{NULL},
/*SSC 0x65*/{NULL},
/*SSC 0x66*/{NULL},
/*SSC 0x67*/{NULL},
/*SSC 0x68*/{NULL},
/*SSC 0x69*/{NULL},
/*SSC 0x6a*/{NULL},
/*SSC 0x6b*/{NULL},
/*SSC 0x6c*/{NULL},
/*SSC 0x6d*/{NULL},
/*SSC 0x6e*/{NULL},
/*SSC 0x6f*/{NULL},
/*SSC 0x70*/{NULL},
/*SSC 0x71*/{NULL},
/*SSC 0x72*/{NULL},
/*SSC 0x73*/{NULL},
/*SSC 0x74*/{NULL},
/*SSC 0x75*/{NULL},
/*SSC 0x76*/{NULL},
/*SSC 0x77*/{NULL},
/*SSC 0x78*/{NULL},
/*SSC 0x79*/{NULL},
/*SSC 0x7a*/{NULL},
/*SSC 0x7b*/{NULL},
/*SSC 0x7c*/{NULL},
/*SSC 0x7d*/{NULL},
/*SSC 0x7e*/{NULL},
/*SSC 0x7f*/{NULL},
/*SSC 0x80*/{NULL},
/*SSC 0x81*/{NULL},
/*SSC 0x82*/{NULL},
/*SSC 0x83*/{NULL},
/*SSC 0x84*/{NULL},
/*SSC 0x85*/{NULL},
/*SSC 0x86*/{NULL},
/*SSC 0x87*/{NULL},
/*SSC 0x88*/{NULL},
/*SSC 0x89*/{NULL},
/*SSC 0x8a*/{NULL},
/*SSC 0x8b*/{NULL},
/*SSC 0x8c*/{NULL},
/*SSC 0x8d*/{NULL},
/*SSC 0x8e*/{NULL},
/*SSC 0x8f*/{NULL},
/*SSC 0x90*/{NULL},
/*SSC 0x91*/{dissect_ssc2_space16},
/*SSC 0x92*/{dissect_ssc2_locate16},
/*SSC 0x93*/{dissect_ssc2_erase16},
/*SSC 0x94*/{NULL},
/*SSC 0x95*/{NULL},
/*SSC 0x96*/{NULL},
/*SSC 0x97*/{NULL},
/*SSC 0x98*/{NULL},
/*SSC 0x99*/{NULL},
/*SSC 0x9a*/{NULL},
/*SSC 0x9b*/{NULL},
/*SSC 0x9c*/{NULL},
/*SSC 0x9d*/{NULL},
/*SSC 0x9e*/{NULL},
/*SSC 0x9f*/{NULL},
/*SSC 0xa0*/{NULL},
/*SSC 0xa1*/{NULL},
/*SSC 0xa2*/{NULL},
/*SSC 0xa3*/{NULL},
/*SSC 0xa4*/{NULL},
/*SSC 0xa5*/{dissect_smc2_movemedium},
/*SSC 0xa6*/{NULL},
/*SSC 0xa7*/{dissect_smc2_movemedium},
/*SSC 0xa8*/{NULL},
/*SSC 0xa9*/{NULL},
/*SSC 0xaa*/{NULL},
/*SSC 0xab*/{NULL},
/*SSC 0xac*/{NULL},
/*SSC 0xad*/{NULL},
/*SSC 0xae*/{NULL},
/*SSC 0xaf*/{NULL},
/*SSC 0xb0*/{NULL},
/*SSC 0xb1*/{NULL},
/*SSC 0xb2*/{NULL},
/*SSC 0xb3*/{NULL},
/*SSC 0xb4*/{dissect_smc2_readelementstatus},
/*SSC 0xb5*/{NULL},
/*SSC 0xb6*/{NULL},
/*SSC 0xb7*/{NULL},
/*SSC 0xb8*/{dissect_smc2_readelementstatus},
/*SSC 0xb9*/{NULL},
/*SSC 0xba*/{NULL},
/*SSC 0xbb*/{NULL},
/*SSC 0xbc*/{NULL},
/*SSC 0xbd*/{NULL},
/*SSC 0xbe*/{NULL},
/*SSC 0xbf*/{NULL},
/*SSC 0xc0*/{NULL},
/*SSC 0xc1*/{NULL},
/*SSC 0xc2*/{NULL},
/*SSC 0xc3*/{NULL},
/*SSC 0xc4*/{NULL},
/*SSC 0xc5*/{NULL},
/*SSC 0xc6*/{NULL},
/*SSC 0xc7*/{NULL},
/*SSC 0xc8*/{NULL},
/*SSC 0xc9*/{NULL},
/*SSC 0xca*/{NULL},
/*SSC 0xcb*/{NULL},
/*SSC 0xcc*/{NULL},
/*SSC 0xcd*/{NULL},
/*SSC 0xce*/{NULL},
/*SSC 0xcf*/{NULL},
/*SSC 0xd0*/{NULL},
/*SSC 0xd1*/{NULL},
/*SSC 0xd2*/{NULL},
/*SSC 0xd3*/{NULL},
/*SSC 0xd4*/{NULL},
/*SSC 0xd5*/{NULL},
/*SSC 0xd6*/{NULL},
/*SSC 0xd7*/{NULL},
/*SSC 0xd8*/{NULL},
/*SSC 0xd9*/{NULL},
/*SSC 0xda*/{NULL},
/*SSC 0xdb*/{NULL},
/*SSC 0xdc*/{NULL},
/*SSC 0xdd*/{NULL},
/*SSC 0xde*/{NULL},
/*SSC 0xdf*/{NULL},
/*SSC 0xe0*/{NULL},
/*SSC 0xe1*/{NULL},
/*SSC 0xe2*/{NULL},
/*SSC 0xe3*/{NULL},
/*SSC 0xe4*/{NULL},
/*SSC 0xe5*/{NULL},
/*SSC 0xe6*/{NULL},
/*SSC 0xe7*/{NULL},
/*SSC 0xe8*/{NULL},
/*SSC 0xe9*/{NULL},
/*SSC 0xea*/{NULL},
/*SSC 0xeb*/{NULL},
/*SSC 0xec*/{NULL},
/*SSC 0xed*/{NULL},
/*SSC 0xee*/{NULL},
/*SSC 0xef*/{NULL},
/*SSC 0xf0*/{NULL},
/*SSC 0xf1*/{NULL},
/*SSC 0xf2*/{NULL},
/*SSC 0xf3*/{NULL},
/*SSC 0xf4*/{NULL},
/*SSC 0xf5*/{NULL},
/*SSC 0xf6*/{NULL},
/*SSC 0xf7*/{NULL},
/*SSC 0xf8*/{NULL},
/*SSC 0xf9*/{NULL},
/*SSC 0xfa*/{NULL},
/*SSC 0xfb*/{NULL},
/*SSC 0xfc*/{NULL},
/*SSC 0xfd*/{NULL},
/*SSC 0xfe*/{NULL},
/*SSC 0xff*/{NULL}
};

static scsi_cdb_table_t smc[256] = {
/*SMC 0x00*/{NULL},
/*SMC 0x01*/{NULL},
/*SMC 0x02*/{NULL},
/*SMC 0x03*/{NULL},
/*SMC 0x04*/{NULL},
/*SMC 0x05*/{NULL},
/*SMC 0x06*/{NULL},
/*SMC 0x07*/{NULL},
/*SMC 0x08*/{NULL},
/*SMC 0x09*/{NULL},
/*SMC 0x0a*/{NULL},
/*SMC 0x0b*/{NULL},
/*SMC 0x0c*/{NULL},
/*SMC 0x0d*/{NULL},
/*SMC 0x0e*/{NULL},
/*SMC 0x0f*/{NULL},
/*SMC 0x10*/{NULL},
/*SMC 0x11*/{NULL},
/*SMC 0x12*/{NULL},
/*SMC 0x13*/{NULL},
/*SMC 0x14*/{NULL},
/*SMC 0x15*/{NULL},
/*SMC 0x16*/{NULL},
/*SMC 0x17*/{NULL},
/*SMC 0x18*/{NULL},
/*SMC 0x19*/{NULL},
/*SMC 0x1a*/{NULL},
/*SMC 0x1b*/{NULL},
/*SMC 0x1c*/{NULL},
/*SMC 0x1d*/{NULL},
/*SMC 0x1e*/{dissect_spc3_preventallowmediaremoval},
/*SMC 0x1f*/{NULL},
/*SMC 0x20*/{NULL},
/*SMC 0x21*/{NULL},
/*SMC 0x22*/{NULL},
/*SMC 0x23*/{NULL},
/*SMC 0x24*/{NULL},
/*SMC 0x25*/{NULL},
/*SMC 0x26*/{NULL},
/*SMC 0x27*/{NULL},
/*SMC 0x28*/{NULL},
/*SMC 0x29*/{NULL},
/*SMC 0x2a*/{NULL},
/*SMC 0x2b*/{NULL},
/*SMC 0x2c*/{NULL},
/*SMC 0x2d*/{NULL},
/*SMC 0x2e*/{NULL},
/*SMC 0x2f*/{NULL},
/*SMC 0x30*/{NULL},
/*SMC 0x31*/{NULL},
/*SMC 0x32*/{NULL},
/*SMC 0x33*/{NULL},
/*SMC 0x34*/{NULL},
/*SMC 0x35*/{NULL},
/*SMC 0x36*/{NULL},
/*SMC 0x37*/{NULL},
/*SMC 0x38*/{NULL},
/*SMC 0x39*/{NULL},
/*SMC 0x3a*/{NULL},
/*SMC 0x3b*/{NULL},
/*SMC 0x3c*/{NULL},
/*SMC 0x3d*/{NULL},
/*SMC 0x3e*/{NULL},
/*SMC 0x3f*/{NULL},
/*SMC 0x40*/{NULL},
/*SMC 0x41*/{NULL},
/*SMC 0x42*/{NULL},
/*SMC 0x43*/{NULL},
/*SMC 0x44*/{NULL},
/*SMC 0x45*/{NULL},
/*SMC 0x46*/{NULL},
/*SMC 0x47*/{NULL},
/*SMC 0x48*/{NULL},
/*SMC 0x49*/{NULL},
/*SMC 0x4a*/{NULL},
/*SMC 0x4b*/{NULL},
/*SMC 0x4c*/{NULL},
/*SMC 0x4d*/{NULL},
/*SMC 0x4e*/{NULL},
/*SMC 0x4f*/{NULL},
/*SMC 0x50*/{NULL},
/*SMC 0x51*/{NULL},
/*SMC 0x52*/{NULL},
/*SMC 0x53*/{NULL},
/*SMC 0x54*/{NULL},
/*SMC 0x55*/{NULL},
/*SMC 0x56*/{NULL},
/*SMC 0x57*/{NULL},
/*SMC 0x58*/{NULL},
/*SMC 0x59*/{NULL},
/*SMC 0x5a*/{NULL},
/*SMC 0x5b*/{NULL},
/*SMC 0x5c*/{NULL},
/*SMC 0x5d*/{NULL},
/*SMC 0x5e*/{NULL},
/*SMC 0x5f*/{NULL},
/*SMC 0x60*/{NULL},
/*SMC 0x61*/{NULL},
/*SMC 0x62*/{NULL},
/*SMC 0x63*/{NULL},
/*SMC 0x64*/{NULL},
/*SMC 0x65*/{NULL},
/*SMC 0x66*/{NULL},
/*SMC 0x67*/{NULL},
/*SMC 0x68*/{NULL},
/*SMC 0x69*/{NULL},
/*SMC 0x6a*/{NULL},
/*SMC 0x6b*/{NULL},
/*SMC 0x6c*/{NULL},
/*SMC 0x6d*/{NULL},
/*SMC 0x6e*/{NULL},
/*SMC 0x6f*/{NULL},
/*SMC 0x70*/{NULL},
/*SMC 0x71*/{NULL},
/*SMC 0x72*/{NULL},
/*SMC 0x73*/{NULL},
/*SMC 0x74*/{NULL},
/*SMC 0x75*/{NULL},
/*SMC 0x76*/{NULL},
/*SMC 0x77*/{NULL},
/*SMC 0x78*/{NULL},
/*SMC 0x79*/{NULL},
/*SMC 0x7a*/{NULL},
/*SMC 0x7b*/{NULL},
/*SMC 0x7c*/{NULL},
/*SMC 0x7d*/{NULL},
/*SMC 0x7e*/{NULL},
/*SMC 0x7f*/{NULL},
/*SMC 0x80*/{NULL},
/*SMC 0x81*/{NULL},
/*SMC 0x82*/{NULL},
/*SMC 0x83*/{NULL},
/*SMC 0x84*/{NULL},
/*SMC 0x85*/{NULL},
/*SMC 0x86*/{NULL},
/*SMC 0x87*/{NULL},
/*SMC 0x88*/{NULL},
/*SMC 0x89*/{NULL},
/*SMC 0x8a*/{NULL},
/*SMC 0x8b*/{NULL},
/*SMC 0x8c*/{NULL},
/*SMC 0x8d*/{NULL},
/*SMC 0x8e*/{NULL},
/*SMC 0x8f*/{NULL},
/*SMC 0x90*/{NULL},
/*SMC 0x91*/{NULL},
/*SMC 0x92*/{NULL},
/*SMC 0x93*/{NULL},
/*SMC 0x94*/{NULL},
/*SMC 0x95*/{NULL},
/*SMC 0x96*/{NULL},
/*SMC 0x97*/{NULL},
/*SMC 0x98*/{NULL},
/*SMC 0x99*/{NULL},
/*SMC 0x9a*/{NULL},
/*SMC 0x9b*/{NULL},
/*SMC 0x9c*/{NULL},
/*SMC 0x9d*/{NULL},
/*SMC 0x9e*/{NULL},
/*SMC 0x9f*/{NULL},
/*SMC 0xa0*/{NULL},
/*SMC 0xa1*/{NULL},
/*SMC 0xa2*/{NULL},
/*SMC 0xa3*/{NULL},
/*SMC 0xa4*/{NULL},
/*SMC 0xa5*/{dissect_smc2_movemedium},
/*SMC 0xa6*/{NULL},
/*SMC 0xa7*/{dissect_smc2_movemedium},
/*SMC 0xa8*/{NULL},
/*SMC 0xa9*/{NULL},
/*SMC 0xaa*/{NULL},
/*SMC 0xab*/{NULL},
/*SMC 0xac*/{NULL},
/*SMC 0xad*/{NULL},
/*SMC 0xae*/{NULL},
/*SMC 0xaf*/{NULL},
/*SMC 0xb0*/{NULL},
/*SMC 0xb1*/{NULL},
/*SMC 0xb2*/{NULL},
/*SMC 0xb3*/{NULL},
/*SMC 0xb4*/{dissect_smc2_readelementstatus},
/*SMC 0xb5*/{NULL},
/*SMC 0xb6*/{NULL},
/*SMC 0xb7*/{NULL},
/*SMC 0xb8*/{dissect_smc2_readelementstatus},
/*SMC 0xb9*/{NULL},
/*SMC 0xba*/{NULL},
/*SMC 0xbb*/{NULL},
/*SMC 0xbc*/{NULL},
/*SMC 0xbd*/{NULL},
/*SMC 0xbe*/{NULL},
/*SMC 0xbf*/{NULL},
/*SMC 0xc0*/{NULL},
/*SMC 0xc1*/{NULL},
/*SMC 0xc2*/{NULL},
/*SMC 0xc3*/{NULL},
/*SMC 0xc4*/{NULL},
/*SMC 0xc5*/{NULL},
/*SMC 0xc6*/{NULL},
/*SMC 0xc7*/{NULL},
/*SMC 0xc8*/{NULL},
/*SMC 0xc9*/{NULL},
/*SMC 0xca*/{NULL},
/*SMC 0xcb*/{NULL},
/*SMC 0xcc*/{NULL},
/*SMC 0xcd*/{NULL},
/*SMC 0xce*/{NULL},
/*SMC 0xcf*/{NULL},
/*SMC 0xd0*/{NULL},
/*SMC 0xd1*/{NULL},
/*SMC 0xd2*/{NULL},
/*SMC 0xd3*/{NULL},
/*SMC 0xd4*/{NULL},
/*SMC 0xd5*/{NULL},
/*SMC 0xd6*/{NULL},
/*SMC 0xd7*/{NULL},
/*SMC 0xd8*/{NULL},
/*SMC 0xd9*/{NULL},
/*SMC 0xda*/{NULL},
/*SMC 0xdb*/{NULL},
/*SMC 0xdc*/{NULL},
/*SMC 0xdd*/{NULL},
/*SMC 0xde*/{NULL},
/*SMC 0xdf*/{NULL},
/*SMC 0xe0*/{NULL},
/*SMC 0xe1*/{NULL},
/*SMC 0xe2*/{NULL},
/*SMC 0xe3*/{NULL},
/*SMC 0xe4*/{NULL},
/*SMC 0xe5*/{NULL},
/*SMC 0xe6*/{NULL},
/*SMC 0xe7*/{NULL},
/*SMC 0xe8*/{NULL},
/*SMC 0xe9*/{NULL},
/*SMC 0xea*/{NULL},
/*SMC 0xeb*/{NULL},
/*SMC 0xec*/{NULL},
/*SMC 0xed*/{NULL},
/*SMC 0xee*/{NULL},
/*SMC 0xef*/{NULL},
/*SMC 0xf0*/{NULL},
/*SMC 0xf1*/{NULL},
/*SMC 0xf2*/{NULL},
/*SMC 0xf3*/{NULL},
/*SMC 0xf4*/{NULL},
/*SMC 0xf5*/{NULL},
/*SMC 0xf6*/{NULL},
/*SMC 0xf7*/{NULL},
/*SMC 0xf8*/{NULL},
/*SMC 0xf9*/{NULL},
/*SMC 0xfa*/{NULL},
/*SMC 0xfb*/{NULL},
/*SMC 0xfc*/{NULL},
/*SMC 0xfd*/{NULL},
/*SMC 0xfe*/{NULL},
/*SMC 0xff*/{NULL}
};

static scsi_cdb_table_t mmc[256] = {
/*MMC 0x00*/{NULL},
/*MMC 0x01*/{NULL},
/*MMC 0x02*/{NULL},
/*MMC 0x03*/{NULL},
/*MMC 0x04*/{NULL},
/*MMC 0x05*/{NULL},
/*MMC 0x06*/{NULL},
/*MMC 0x07*/{NULL},
/*MMC 0x08*/{NULL},
/*MMC 0x09*/{NULL},
/*MMC 0x0a*/{NULL},
/*MMC 0x0b*/{NULL},
/*MMC 0x0c*/{NULL},
/*MMC 0x0d*/{NULL},
/*MMC 0x0e*/{NULL},
/*MMC 0x0f*/{NULL},
/*MMC 0x10*/{NULL},
/*MMC 0x11*/{NULL},
/*MMC 0x12*/{NULL},
/*MMC 0x13*/{NULL},
/*MMC 0x14*/{NULL},
/*MMC 0x15*/{NULL},
/*MMC 0x16*/{NULL},
/*MMC 0x17*/{NULL},
/*MMC 0x18*/{NULL},
/*MMC 0x19*/{NULL},
/*MMC 0x1a*/{NULL},
/*MMC 0x1b*/{dissect_sbc2_startstopunit},
/*MMC 0x1c*/{NULL},
/*MMC 0x1d*/{NULL},
/*MMC 0x1e*/{dissect_spc3_preventallowmediaremoval},
/*MMC 0x1f*/{NULL},
/*MMC 0x20*/{NULL},
/*MMC 0x21*/{NULL},
/*MMC 0x22*/{NULL},
/*MMC 0x23*/{NULL},
/*MMC 0x24*/{NULL},
/*MMC 0x25*/{dissect_sbc2_readcapacity10},
/*MMC 0x26*/{NULL},
/*MMC 0x27*/{NULL},
/*MMC 0x28*/{dissect_sbc2_readwrite10},
/*MMC 0x29*/{NULL},
/*MMC 0x2a*/{dissect_sbc2_readwrite10},
/*MMC 0x2b*/{NULL},
/*MMC 0x2c*/{NULL},
/*MMC 0x2d*/{NULL},
/*MMC 0x2e*/{NULL},
/*MMC 0x2f*/{NULL},
/*MMC 0x30*/{NULL},
/*MMC 0x31*/{NULL},
/*MMC 0x32*/{NULL},
/*MMC 0x33*/{NULL},
/*MMC 0x34*/{NULL},
/*MMC 0x35*/{dissect_mmc4_synchronizecache},
/*MMC 0x36*/{NULL},
/*MMC 0x37*/{NULL},
/*MMC 0x38*/{NULL},
/*MMC 0x39*/{NULL},
/*MMC 0x3a*/{NULL},
/*MMC 0x3b*/{NULL},
/*MMC 0x3c*/{NULL},
/*MMC 0x3d*/{NULL},
/*MMC 0x3e*/{NULL},
/*MMC 0x3f*/{NULL},
/*MMC 0x40*/{NULL},
/*MMC 0x41*/{NULL},
/*MMC 0x42*/{NULL},
/*MMC 0x43*/{dissect_mmc4_readtocpmaatip},
/*MMC 0x44*/{NULL},
/*MMC 0x45*/{NULL},
/*MMC 0x46*/{dissect_mmc4_getconfiguration},
/*MMC 0x47*/{NULL},
/*MMC 0x48*/{NULL},
/*MMC 0x49*/{NULL},
/*MMC 0x4a*/{dissect_mmc4_geteventstatusnotification},
/*MMC 0x4b*/{NULL},
/*MMC 0x4c*/{NULL},
/*MMC 0x4d*/{NULL},
/*MMC 0x4e*/{NULL},
/*MMC 0x4f*/{NULL},
/*MMC 0x50*/{NULL},
/*MMC 0x51*/{dissect_mmc4_readdiscinformation},
/*MMC 0x52*/{dissect_mmc4_readtrackinformation},
/*MMC 0x53*/{dissect_mmc4_reservetrack},
/*MMC 0x54*/{NULL},
/*MMC 0x55*/{NULL},
/*MMC 0x56*/{NULL},
/*MMC 0x57*/{NULL},
/*MMC 0x58*/{NULL},
/*MMC 0x59*/{NULL},
/*MMC 0x5a*/{NULL},
/*MMC 0x5b*/{NULL},
/*MMC 0x5c*/{dissect_mmc4_readbuffercapacity},
/*MMC 0x5d*/{NULL},
/*MMC 0x5e*/{NULL},
/*MMC 0x5f*/{NULL},
/*MMC 0x60*/{NULL},
/*MMC 0x61*/{NULL},
/*MMC 0x62*/{NULL},
/*MMC 0x63*/{NULL},
/*MMC 0x64*/{NULL},
/*MMC 0x65*/{NULL},
/*MMC 0x66*/{NULL},
/*MMC 0x67*/{NULL},
/*MMC 0x68*/{NULL},
/*MMC 0x69*/{NULL},
/*MMC 0x6a*/{NULL},
/*MMC 0x6b*/{NULL},
/*MMC 0x6c*/{NULL},
/*MMC 0x6d*/{NULL},
/*MMC 0x6e*/{NULL},
/*MMC 0x6f*/{NULL},
/*MMC 0x70*/{NULL},
/*MMC 0x71*/{NULL},
/*MMC 0x72*/{NULL},
/*MMC 0x73*/{NULL},
/*MMC 0x74*/{NULL},
/*MMC 0x75*/{NULL},
/*MMC 0x76*/{NULL},
/*MMC 0x77*/{NULL},
/*MMC 0x78*/{NULL},
/*MMC 0x79*/{NULL},
/*MMC 0x7a*/{NULL},
/*MMC 0x7b*/{NULL},
/*MMC 0x7c*/{NULL},
/*MMC 0x7d*/{NULL},
/*MMC 0x7e*/{NULL},
/*MMC 0x7f*/{NULL},
/*MMC 0x80*/{NULL},
/*MMC 0x81*/{NULL},
/*MMC 0x82*/{NULL},
/*MMC 0x83*/{NULL},
/*MMC 0x84*/{NULL},
/*MMC 0x85*/{NULL},
/*MMC 0x86*/{NULL},
/*MMC 0x87*/{NULL},
/*MMC 0x88*/{NULL},
/*MMC 0x89*/{NULL},
/*MMC 0x8a*/{NULL},
/*MMC 0x8b*/{NULL},
/*MMC 0x8c*/{NULL},
/*MMC 0x8d*/{NULL},
/*MMC 0x8e*/{NULL},
/*MMC 0x8f*/{NULL},
/*MMC 0x90*/{NULL},
/*MMC 0x91*/{NULL},
/*MMC 0x92*/{NULL},
/*MMC 0x93*/{NULL},
/*MMC 0x94*/{NULL},
/*MMC 0x95*/{NULL},
/*MMC 0x96*/{NULL},
/*MMC 0x97*/{NULL},
/*MMC 0x98*/{NULL},
/*MMC 0x99*/{NULL},
/*MMC 0x9a*/{NULL},
/*MMC 0x9b*/{NULL},
/*MMC 0x9c*/{NULL},
/*MMC 0x9d*/{NULL},
/*MMC 0x9e*/{NULL},
/*MMC 0x9f*/{NULL},
/*MMC 0xa0*/{NULL},
/*MMC 0xa1*/{NULL},
/*MMC 0xa2*/{NULL},
/*MMC 0xa3*/{NULL},
/*MMC 0xa4*/{dissect_mmc4_reportkey},
/*MMC 0xa5*/{NULL},
/*MMC 0xa6*/{NULL},
/*MMC 0xa7*/{NULL},
/*MMC 0xa8*/{dissect_sbc2_readwrite12},
/*MMC 0xa9*/{NULL},
/*MMC 0xaa*/{dissect_sbc2_readwrite12},
/*MMC 0xab*/{NULL},
/*MMC 0xac*/{dissect_mmc4_getperformance},
/*MMC 0xad*/{dissect_mmc4_readdiscstructure},
/*MMC 0xae*/{NULL},
/*MMC 0xaf*/{NULL},
/*MMC 0xb0*/{NULL},
/*MMC 0xb1*/{NULL},
/*MMC 0xb2*/{NULL},
/*MMC 0xb3*/{NULL},
/*MMC 0xb4*/{NULL},
/*MMC 0xb5*/{NULL},
/*MMC 0xb6*/{dissect_mmc4_setstreaming},
/*MMC 0xb7*/{NULL},
/*MMC 0xb8*/{NULL},
/*MMC 0xb9*/{NULL},
/*MMC 0xba*/{NULL},
/*MMC 0xbb*/{dissect_mmc4_setcdspeed},
/*MMC 0xbc*/{NULL},
/*MMC 0xbd*/{NULL},
/*MMC 0xbe*/{NULL},
/*MMC 0xbf*/{NULL},
/*MMC 0xc0*/{NULL},
/*MMC 0xc1*/{NULL},
/*MMC 0xc2*/{NULL},
/*MMC 0xc3*/{NULL},
/*MMC 0xc4*/{NULL},
/*MMC 0xc5*/{NULL},
/*MMC 0xc6*/{NULL},
/*MMC 0xc7*/{NULL},
/*MMC 0xc8*/{NULL},
/*MMC 0xc9*/{NULL},
/*MMC 0xca*/{NULL},
/*MMC 0xcb*/{NULL},
/*MMC 0xcc*/{NULL},
/*MMC 0xcd*/{NULL},
/*MMC 0xce*/{NULL},
/*MMC 0xcf*/{NULL},
/*MMC 0xd0*/{NULL},
/*MMC 0xd1*/{NULL},
/*MMC 0xd2*/{NULL},
/*MMC 0xd3*/{NULL},
/*MMC 0xd4*/{NULL},
/*MMC 0xd5*/{NULL},
/*MMC 0xd6*/{NULL},
/*MMC 0xd7*/{NULL},
/*MMC 0xd8*/{NULL},
/*MMC 0xd9*/{NULL},
/*MMC 0xda*/{NULL},
/*MMC 0xdb*/{NULL},
/*MMC 0xdc*/{NULL},
/*MMC 0xdd*/{NULL},
/*MMC 0xde*/{NULL},
/*MMC 0xdf*/{NULL},
/*MMC 0xe0*/{NULL},
/*MMC 0xe1*/{NULL},
/*MMC 0xe2*/{NULL},
/*MMC 0xe3*/{NULL},
/*MMC 0xe4*/{NULL},
/*MMC 0xe5*/{NULL},
/*MMC 0xe6*/{NULL},
/*MMC 0xe7*/{NULL},
/*MMC 0xe8*/{NULL},
/*MMC 0xe9*/{NULL},
/*MMC 0xea*/{NULL},
/*MMC 0xeb*/{NULL},
/*MMC 0xec*/{NULL},
/*MMC 0xed*/{NULL},
/*MMC 0xee*/{NULL},
/*MMC 0xef*/{NULL},
/*MMC 0xf0*/{NULL},
/*MMC 0xf1*/{NULL},
/*MMC 0xf2*/{NULL},
/*MMC 0xf3*/{NULL},
/*MMC 0xf4*/{NULL},
/*MMC 0xf5*/{NULL},
/*MMC 0xf6*/{NULL},
/*MMC 0xf7*/{NULL},
/*MMC 0xf8*/{NULL},
/*MMC 0xf9*/{NULL},
/*MMC 0xfa*/{NULL},
/*MMC 0xfb*/{NULL},
/*MMC 0xfc*/{NULL},
/*MMC 0xfd*/{NULL},
/*MMC 0xfe*/{NULL},
/*MMC 0xff*/{NULL}
};

void
dissect_scsi_cdb (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  gint devtype_arg, guint16 lun)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode;
    scsi_device_type devtype;
    scsi_cmnd_type cmd = 0;     /* 0 is undefined type */
    const gchar *valstr;
    scsi_task_data_t *cdata;
    scsi_devtype_key_t dkey;
    scsi_devtype_data_t *devdata;
    scsi_cdb_table_t *cdb_table=NULL;
    const value_string *cdb_vals = NULL;
    int hf_opcode=-1;
    char *old_proto;

    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    opcode = tvb_get_guint8 (tvb, offset);

    if (devtype_arg != SCSI_DEV_UNKNOWN) {
        devtype = devtype_arg;
    } else {
        /*
         * Try to look up the device data for this device.
         *
         * We don't use COPY_ADDRESS because "dkey.devid" isn't
         * persistent, and therefore it can point to the stuff
         * in "pinfo->src".  (Were we to use COPY_ADDRESS, we'd
         * have to free the address data it allocated before we return.)
         */
        dkey.devid = pinfo->dst;

        devdata = (scsi_devtype_data_t *)g_hash_table_lookup (scsidev_req_hash,
                                                              &dkey);
        if (devdata != NULL) {
            devtype = devdata->devtype;
        } else {
            devtype = (scsi_device_type)scsi_def_devtype;
        }
    }

    if ((valstr = match_strval (opcode, scsi_spc2_val)) == NULL) {
        /*
         * This isn't a generic command that applies to all SCSI
         * device types; try to interpret it based on what we deduced,
         * or were told, the device type is.
         *
         * Right now, the only choices are SBC or SSC. If we ever expand
         * this to decode other device types, this piece of code needs to
         * be modified.
         */
        switch (devtype) {
        case SCSI_DEV_SBC:
            valstr = match_strval (opcode, scsi_sbc2_val);
            cmd = SCSI_CMND_SBC2;
            cdb_table=sbc;
            cdb_vals=scsi_sbc2_val;
            hf_opcode=hf_scsi_sbcopcode;
            break;

        case SCSI_DEV_CDROM:
            valstr = match_strval (opcode, scsi_mmc_val);
            cmd = SCSI_CMND_MMC;
            cdb_table=mmc;
            cdb_vals=scsi_mmc_val;
            hf_opcode=hf_scsi_mmcopcode;
            break;

        case SCSI_DEV_SSC:
            valstr = match_strval (opcode, scsi_ssc2_val);
            cmd = SCSI_CMND_SSC2;
            cdb_table=ssc;
            cdb_vals=scsi_ssc2_val;
            hf_opcode=hf_scsi_sscopcode;
            break;

        case SCSI_DEV_SMC:
            valstr = match_strval (opcode, scsi_smc2_val);
            cmd = SCSI_CMND_SMC2;
            cdb_table=smc;
            cdb_vals=scsi_smc2_val;
            hf_opcode=hf_scsi_smcopcode;
            break;

        default:
            cmd = SCSI_CMND_SPC2;
            cdb_table=spc;
            cdb_vals=scsi_spc2_val;
            hf_opcode=hf_scsi_spcopcode;
            break;
        }
    } else {
        cmd = SCSI_CMND_SPC2;
        cdb_table=spc;
        cdb_vals=scsi_spc2_val;
        hf_opcode=hf_scsi_spcopcode;
    }

    if (valstr != NULL) {
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI: %s LUN: 0x%02x ", valstr, lun);
        }
    } else {
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI Command: 0x%02x LUN:0x%02x ", opcode, lun);
        }
    }

    cdata = scsi_new_task (pinfo);

    if (cdata) {
        cdata->opcode = opcode;
        cdata->cmd = cmd;
        cdata->devtype = devtype;
	cdata->flags = 0;
	cdata->cdb_table = cdb_table;
	cdata->cdb_vals = cdb_vals;
    }

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, 0,
                                             -1, "SCSI CDB %s",
                                             val_to_str (opcode,
                                                         cdb_vals,
                                                         "0x%02x")
                                             );
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);

	ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, lun);
	PROTO_ITEM_SET_GENERATED(ti);


        if (valstr != NULL) {
            proto_tree_add_uint_format (scsi_tree, hf_opcode, tvb,
                                        offset, 1,
                                        tvb_get_guint8 (tvb, offset),
                                        "Opcode: %s (0x%02x)", valstr,
                                        opcode);
        } else {
            proto_tree_add_item (scsi_tree, hf_scsi_spcopcode, tvb, offset, 1, 0);
        }
    }

    /*
       All commandsets support SPC?
    */
    if(cdb_table && cdb_table[opcode].func){
        cdb_table[opcode].func(tvb, pinfo, scsi_tree, offset+1,
                               TRUE, TRUE, 0, cdata);
    } else if(spc[opcode].func){
        spc[opcode].func(tvb, pinfo, scsi_tree, offset+1,
                               TRUE, TRUE, 0, cdata);
    } else {
        call_dissector (data_handle, tvb, pinfo, scsi_tree);
    }

    pinfo->current_proto=old_proto;
}

void
dissect_scsi_payload (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      gboolean isreq, guint16 lun)
{
    int offset=0;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode = 0xFF;
    scsi_device_type devtype;
    scsi_task_data_t *cdata = NULL;
    int payload_len;
    char *old_proto;

    payload_len=tvb_length(tvb);
    cdata = scsi_find_task (pinfo);

    if (!cdata) {
        /* we have no record of this exchange and so we can't dissect the
         * payload
         */
        return;
    }

    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    opcode = cdata->opcode;
    devtype = cdata->devtype;

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                             payload_len,
                                             "SCSI Payload (%s %s)",
                                             val_to_str (opcode,
                                                         cdata->cdb_vals,
                                                         "0x%02x"),
                                             isreq ? "Request" : "Response");
	if (check_col (pinfo->cinfo, COL_INFO)) {
	    col_add_fstr (pinfo->cinfo, COL_INFO,
			"SCSI: Data %s LUN: 0x%02x (%s %s) ",
			isreq ? "Out" : "In",
			lun,
			val_to_str (opcode, cdata->cdb_vals, "0x%02x"),
			isreq ? "Request" : "Response");
	}
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);
    }

    if(tree){
	ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, lun);
	PROTO_ITEM_SET_GENERATED(ti);
    }

    if (tree == NULL) {
        /*
         * We have to dissect INQUIRY responses, in order to determine the
         * types of devices.
         *
         * We don't bother dissecting other payload if we're not buildng
         * a protocol tree.
         *
	 * We assume opcode 0x12 is always INQUIRY regardless of the
	 * commandset used.
	 */
        if (opcode == SCSI_SPC2_INQUIRY) {
            dissect_spc3_inquiry (tvb, pinfo, scsi_tree, offset, isreq,
                                  FALSE, payload_len, cdata);
        }
    } else {
        /*
           All commandsets support SPC?
        */
        if(cdata->cdb_table && (cdata->cdb_table)[opcode].func){
            (cdata->cdb_table)[opcode].func(tvb, pinfo, scsi_tree, offset,
                               isreq, FALSE, payload_len, cdata);
        } else if(spc[opcode].func){
            spc[opcode].func(tvb, pinfo, scsi_tree, offset,
                               isreq, FALSE, payload_len, cdata);
        } else { /* dont know this CDB */
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
        }
    }

    pinfo->current_proto=old_proto;
}

void
proto_register_scsi (void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	/*16 bit to print something useful for weirdo
		volume set addressing hosts*/
       { &hf_scsi_lun,
          {"LUN", "scsi.lun", FT_UINT16, BASE_HEX,
           NULL, 0x0, "LUN", HFILL}},
	{ &hf_scsi_status,
	  { "Status", "scsi.status", FT_UINT8, BASE_HEX,
	   VALS(scsi_status_val), 0, "SCSI command status value", HFILL }},
        { &hf_scsi_spcopcode,
          {"SPC-2 Opcode", "scsi.spc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc2_val), 0x0, "", HFILL}},
        { &hf_scsi_mmcopcode,
          {"MMC Opcode", "scsi.mmc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_mmc_val), 0x0, "", HFILL}},
        { &hf_scsi_sbcopcode,
          {"SBC-2 Opcode", "scsi.sbc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc2_val), 0x0, "", HFILL}},
        { &hf_scsi_sscopcode,
          {"SSC-2 Opcode", "scsi.ssc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_ssc2_val), 0x0, "", HFILL}},
        { &hf_scsi_smcopcode,
          {"SMC-2 Opcode", "scsi.smc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_smc2_val), 0x0, "", HFILL}},
        { &hf_scsi_control,
          {"Control", "scsi.cdb.control", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_inquiry_flags,
          {"Flags", "scsi.inquiry.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_inquiry_evpd_page,
          {"EVPD Page Code", "scsi.inquiry.evpd.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_evpd_pagecode_val), 0x0, "", HFILL}},
        { &hf_scsi_inquiry_cmdt_page,
          {"CMDT Page Code", "scsi.inquiry.cmdt.pagecode", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_alloclen,
          {"Allocation Length", "scsi.cdb.alloclen", FT_UINT8, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_logsel_flags,
          {"Flags", "scsi.logsel.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_logsel_pc,
          {"Page Control", "scsi.logsel.pc", FT_UINT8, BASE_DEC,
           VALS (scsi_logsel_pc_val), 0xC0, "", HFILL}},
        { &hf_scsi_paramlen,
          {"Parameter Length", "scsi.cdb.paramlen", FT_UINT8, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_logsns_flags,
          {"Flags", "scsi.logsns.flags", FT_UINT16, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_logsns_pc,
          {"Page Control", "scsi.logsns.pc", FT_UINT8, BASE_DEC,
           VALS (scsi_logsns_pc_val), 0xC0, "", HFILL}},
        { &hf_scsi_logsns_pagecode,
          {"Page Code", "scsi.logsns.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_logsns_page_val), 0x3F0, "", HFILL}},
        { &hf_scsi_paramlen16,
          {"Parameter Length", "scsi.cdb.paramlen16", FT_UINT16, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_modesel_flags,
          {"Mode Sense/Select Flags", "scsi.cdb.mode.flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_alloclen16,
          {"Allocation Length", "scsi.cdb.alloclen16", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_modesns_pc,
          {"Page Control", "scsi.mode.pc", FT_UINT8, BASE_DEC,
           VALS (scsi_modesns_pc_val), 0xC0, "", HFILL}},
        { &hf_scsi_spcpagecode,
          {"SPC-2 Page Code", "scsi.mode.spc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc2_modepage_val), 0x3F, "", HFILL}},
        { &hf_scsi_sbcpagecode,
          {"SBC-2 Page Code", "scsi.mode.sbc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc2_modepage_val), 0x3F, "", HFILL}},
        { &hf_scsi_sscpagecode,
          {"SSC-2 Page Code", "scsi.mode.ssc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_ssc2_modepage_val), 0x3F, "", HFILL}},
        { &hf_scsi_mmcpagecode,
          {"MMC-5 Page Code", "scsi.mode.mmc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_mmc5_modepage_val), 0x3F, "", HFILL}},
        { &hf_scsi_smcpagecode,
          {"SMC-2 Page Code", "scsi.mode.smc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_smc2_modepage_val), 0x3F, "", HFILL}},
        { &hf_scsi_modesns_flags,
          {"Flags", "scsi.mode.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_persresvin_svcaction,
          {"Service Action", "scsi.persresvin.svcaction", FT_UINT8, BASE_HEX,
           VALS (scsi_persresvin_svcaction_val), 0x0F, "", HFILL}},
        { &hf_scsi_persresvout_svcaction,
          {"Service Action", "scsi.persresvout.svcaction", FT_UINT8, BASE_HEX,
           VALS (scsi_persresvout_svcaction_val), 0x0F, "", HFILL}},
        { &hf_scsi_persresv_scope,
          {"Reservation Scope", "scsi.persresv.scope", FT_UINT8, BASE_HEX,
           VALS (scsi_persresv_scope_val), 0xF0, "", HFILL}},
        { &hf_scsi_persresv_type,
          {"Reservation Type", "scsi.persresv.type", FT_UINT8, BASE_HEX,
           VALS (scsi_persresv_type_val), 0x0F, "", HFILL}},
        { &hf_scsi_release_flags,
          {"Release Flags", "scsi.release.flags", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_release_thirdpartyid,
          {"Third-Party ID", "scsi.release.thirdpartyid", FT_BYTES, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_alloclen32,
          {"Allocation Length", "scsi.cdb.alloclen32", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_formatunit_flags,
          {"Flags", "scsi.formatunit.flags", FT_UINT8, BASE_HEX, NULL, 0xF8,
           "", HFILL}},
        { &hf_scsi_cdb_defectfmt,
          {"Defect List Format", "scsi.cdb.defectfmt", FT_UINT8, BASE_DEC,
           NULL, 0x7, "", HFILL}},
        { &hf_scsi_formatunit_interleave,
          {"Interleave", "scsi.formatunit.interleave", FT_UINT16, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_formatunit_vendor,
          {"Vendor Unique", "scsi.formatunit.vendor", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_rdwr6_lba,
          {"Logical Block Address (LBA)", "scsi.rdwr6.lba", FT_UINT24, BASE_DEC,
           NULL, 0x0FFFFF, "", HFILL}},
        { &hf_scsi_rdwr6_xferlen,
          {"Transfer Length", "scsi.rdwr6.xferlen", FT_UINT24, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_rdwr10_lba,
          {"Logical Block Address (LBA)", "scsi.rdwr10.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_rdwr10_xferlen,
          {"Transfer Length", "scsi.rdwr10.xferlen", FT_UINT16, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_read_flags,
          {"Flags", "scsi.read.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_rdwr12_xferlen,
          {"Transfer Length", "scsi.rdwr12.xferlen", FT_UINT32, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_rdwr16_lba,
          {"Logical Block Address (LBA)", "scsi.rdwr16.lba", FT_BYTES, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_readcapacity_flags,
          {"Flags", "scsi.readcapacity.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_readcapacity_lba,
          {"Logical Block Address", "scsi.readcapacity.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_readcapacity_pmi,
          {"PMI", "scsi.readcapacity.pmi", FT_UINT8, BASE_DEC, NULL, 0x1, "",
           HFILL}},
        { &hf_scsi_readdefdata_flags,
          {"Flags", "scsi.readdefdata.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_reassignblks_flags,
          {"Flags", "scsi.reassignblks.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_inq_qualifier,
          {"Peripheral Qualifier", "scsi.inquiry.qualifier", FT_UINT8, BASE_HEX,
           VALS (scsi_qualifier_val), 0xE0, "", HFILL}},
        { &hf_scsi_inq_devtype,
          {"Peripheral Device Type", "scsi.inquiry.devtype", FT_UINT8, BASE_HEX,
           VALS (scsi_devtype_val), SCSI_DEV_BITS, "", HFILL}},
        { &hf_scsi_inq_rmb,
          {"Removable", "scsi.inquiry.removable", FT_BOOLEAN, 8,
           TFS (&scsi_removable_val), 0x80, "", HFILL}},
        { & hf_scsi_inq_version,
          {"Version", "scsi.inquiry.version", FT_UINT8, BASE_HEX,
           VALS (scsi_inquiry_vers_val), 0x0, "", HFILL}},
        { &hf_scsi_inq_normaca,
          {"NormACA", "scsi.inquiry.normaca", FT_UINT8, BASE_HEX, NULL, 0x20,
           "", HFILL}},
        { &hf_scsi_rluns_lun,
          {"LUN", "scsi.reportluns.lun", FT_UINT8, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_rluns_multilun,
          {"Multi-level LUN", "scsi.reportluns.mlun", FT_BYTES, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_modesns_errrep,
          {"MRIE", "scsi.mode.mrie", FT_UINT8, BASE_HEX,
           VALS (scsi_modesns_mrie_val), 0x0F, "", HFILL}},
        { &hf_scsi_modesns_tst,
          {"Task Set Type", "scsi.mode.tst", FT_UINT8, BASE_DEC,
           VALS (scsi_modesns_tst_val), 0xE0, "", HFILL}},
        { &hf_scsi_modesns_qmod,
          {"Queue Algorithm Modifier", "scsi.mode.qmod", FT_UINT8, BASE_HEX,
           VALS (scsi_modesns_qmod_val), 0xF0, "", HFILL}},
        { &hf_scsi_modesns_qerr,
          {"Queue Error Management", "scsi.mode.qerr", FT_BOOLEAN, BASE_HEX,
           TFS (&scsi_modesns_qerr_val), 0x2, "", HFILL}},
        { &hf_scsi_modesns_tas,
          {"Task Aborted Status", "scsi.mode.tac", FT_BOOLEAN, BASE_HEX,
           TFS (&scsi_modesns_tas_val), 0x80, "", HFILL}},
        { &hf_scsi_modesns_rac,
          {"Report a Check", "ssci.mode.rac", FT_BOOLEAN, BASE_HEX,
           TFS (&scsi_modesns_rac_val), 0x40, "", HFILL}},
        { &hf_scsi_protocol,
          {"Protocol", "scsi.proto", FT_UINT8, BASE_DEC, VALS (scsi_proto_val),
           0x0F, "", HFILL}},
        { &hf_scsi_sns_errtype,
          {"SNS Error Type", "scsi.sns.errtype", FT_UINT8, BASE_HEX,
           VALS (scsi_sns_errtype_val), 0x7F, "", HFILL}},
        { &hf_scsi_snskey,
          {"Sense Key", "scsi.sns.key", FT_UINT8, BASE_HEX,
           VALS (scsi_sensekey_val), 0x0F, "", HFILL}},
        { &hf_scsi_snsinfo,
          {"Sense Info", "scsi.sns.info", FT_UINT32, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_addlsnslen,
          {"Additional Sense Length", "scsi.sns.addlen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_asc,
          {"Additional Sense Code", "scsi.sns.asc", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_ascq,
          {"Additional Sense Code Qualifier", "scsi.sns.ascq", FT_UINT8,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_scsi_ascascq,
          {"Additional Sense Code+Qualifier", "scsi.sns.ascascq", FT_UINT16,
           BASE_HEX, VALS (scsi_asc_val), 0x0, "", HFILL}},
        { &hf_scsi_fru,
          {"Field Replaceable Unit Code", "scsi.sns.fru", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sksv,
          {"SKSV", "scsi.sns.sksv", FT_BOOLEAN, BASE_HEX, NULL, 0x80, "",
           HFILL}},
        { &hf_scsi_persresv_key,
          {"Reservation Key", "scsi.spc2.resv.key", FT_BYTES, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_persresv_scopeaddr,
          {"Scope Address", "scsi.spc2.resv.scopeaddr", FT_BYTES, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_add_cdblen,
          {"Additional CDB Length", "scsi.spc2.addcdblen", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_svcaction,
          {"Service Action", "scsi.spc2.svcaction", FT_UINT16, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_ssu_immed,
          {"Immediate", "scsi.sbc2.ssu.immediate", FT_BOOLEAN, BASE_DEC, NULL,
           0x1, "", HFILL}},
        { &hf_scsi_ssu_pwr_cond,
          {"Power Conditions", "scsi.sbc2.ssu.pwr", FT_UINT8, BASE_HEX,
           VALS (scsi_ssu_pwrcnd_val), 0xF0, "", HFILL}},
        { &hf_scsi_ssu_loej,
          {"LOEJ", "scsi.sbc2.ssu.loej", FT_BOOLEAN, BASE_HEX, NULL, 0x2, "",
           HFILL}},
        { &hf_scsi_ssu_start,
          {"Start", "scsi.sbc2.ssu.start", FT_BOOLEAN, BASE_HEX, NULL, 0x1,
           "", HFILL}},
        { &hf_scsi_wb_mode,
          {"Mode", "scsi.spc2.wb.mode", FT_UINT8, BASE_HEX,
           VALS (scsi_wb_mode_val), 0xF, "", HFILL}},
        { &hf_scsi_wb_bufferid,
          {"Buffer ID", "scsi.spc2.sb.bufid", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_wb_bufoffset,
          {"Buffer Offset", "scsi.spc2.wb.bufoff", FT_UINT24, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_paramlen24,
          {"Paremeter List Length", "scsi.cdb.paramlen24", FT_UINT24, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_senddiag_st_code,
          {"Self-Test Code", "scsi.spc2.senddiag.code", FT_UINT8, BASE_HEX,
           VALS (scsi_senddiag_st_code_val), 0xE0, "", HFILL}},
        { &hf_scsi_select_report,
          {"Select Report", "scsi.spc2.select_report", FT_UINT8, BASE_HEX,
           VALS (scsi_select_report_val), 0x00, "", HFILL}},
        { &hf_scsi_senddiag_pf,
          {"PF", "scsi.spc2.senddiag.pf", FT_BOOLEAN, BASE_HEX,
           TFS (&scsi_senddiag_pf_val), 0x10, "", HFILL}},
        { &hf_scsi_senddiag_st,
          {"Self Test", "scsi.spc2.senddiag.st", FT_BOOLEAN, BASE_HEX, NULL,
           0x4, "", HFILL}},
        { &hf_scsi_senddiag_devoff,
          {"Device Offline", "scsi.spc2.senddiag.devoff", FT_BOOLEAN, BASE_HEX,
           NULL, 0x2, "", HFILL}},
        { &hf_scsi_senddiag_unitoff,
          {"Unit Offline", "scsi.spc2.senddiag.unitoff", FT_BOOLEAN, BASE_HEX,
           NULL, 0x1, "", HFILL}},
        { &hf_scsi_key_class,
          {"Key Class", "scsi.mmc4.key_class", FT_UINT8, BASE_HEX,
           VALS (scsi_key_class_val), 0x00, "", HFILL}},
        { &hf_scsi_agid,
          {"AGID", "scsi.mmc4.agid", FT_UINT8, BASE_HEX,
           NULL, 0xc0, "", HFILL}},
        { &hf_scsi_key_format,
          {"Key Format", "scsi.mmc4.key_format", FT_UINT8, BASE_HEX,
           VALS (scsi_key_format_val), 0x3f, "", HFILL}},
        { &hf_scsi_lba,
          {"Logical Block Address", "scsi.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_num_blocks,
          {"Number of Blocks", "scsi.num_blocks", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_data_length,
          {"Data Length", "scsi.data_length", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_report_key_type_code,
          {"Type Code", "scsi.report_key.type_code", FT_UINT8, BASE_HEX,
           VALS(scsi_report_key_type_code_val), 0xc0, "", HFILL}},
        { &hf_scsi_report_key_vendor_resets,
          {"Vendor Resets", "scsi.report_key.vendor_resets", FT_UINT8, BASE_HEX,
           NULL, 0x38, "", HFILL}},
        { &hf_scsi_report_key_user_changes,
          {"User Changes", "scsi.report_key.user_changes", FT_UINT8, BASE_HEX,
           NULL, 0x07, "", HFILL}},
        { &hf_scsi_report_key_region_mask,
          {"Region Mask", "scsi.report_key.region_mask", FT_UINT8, BASE_HEX,
           NULL, 0xff, "", HFILL}},
        { &hf_scsi_report_key_rpc_scheme,
          {"RPC Scheme", "scsi.report_key.rpc_scheme", FT_UINT8, BASE_HEX,
           VALS(scsi_report_key_rpc_scheme_val), 0, "", HFILL}},
        { &hf_scsi_setcdspeed_rc,
          {"Rotational Control", "scsi.setcdspeed.rc", FT_UINT8, BASE_HEX,
           VALS(scsi_setcdspeed_rc_val), 0x03, "", HFILL}},
        { &hf_scsi_getconf_rt,
          {"RT", "scsi.getconf.rt", FT_UINT8, BASE_HEX,
           VALS(scsi_getconf_rt_val), 0x03, "", HFILL}},
        { &hf_scsi_getconf_current_profile,
          {"Current Profile", "scsi.getconf.current_profile", FT_UINT16, BASE_HEX,
           VALS(scsi_getconf_current_profile_val), 0, "", HFILL}},
        { &hf_scsi_getconf_starting_feature,
          {"Starting Feature", "scsi.getconf.starting_feature", FT_UINT16, BASE_HEX,
           VALS(scsi_feature_val), 0, "", HFILL}},
        { &hf_scsi_feature,
          {"Feature", "scsi.feature", FT_UINT16, BASE_HEX,
           VALS(scsi_feature_val), 0, "", HFILL}},
        { &hf_scsi_feature_version,
          {"Version", "scsi.feature.version", FT_UINT8, BASE_DEC,
           NULL, 0x3c, "", HFILL}},
        { &hf_scsi_feature_persistent,
          {"Persistent", "scsi.feature.persistent", FT_UINT8, BASE_HEX,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_current,
          {"Current", "scsi.feature.current", FT_UINT8, BASE_HEX,
           NULL, 001, "", HFILL}},
        { &hf_scsi_feature_additional_length,
          {"Additional Length", "scsi.feature.additional_length", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_feature_lun_sn,
          {"LUN Serial Number", "scsi.feature.lun_sn", FT_STRING, BASE_NONE,
           NULL, 0, "", HFILL}},
        { &hf_scsi_feature_cdread_dap,
          {"DAP", "scsi.feature.cdread.dap", FT_BOOLEAN, 8,
           NULL, 0x80, "", HFILL}},
        { &hf_scsi_feature_cdread_c2flag,
          {"C2 Flag", "scsi.feature.cdread.c2flag", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_cdread_cdtext,
          {"CD-Text", "scsi.feature.cdread.cdtext", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_dvdrw_write,
          {"Write", "scsi.feature.dvdrw.write", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_dvdrw_quickstart,
          {"Quick Start", "scsi.feature.dvdrw.quickstart", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_dvdrw_closeonly,
          {"Close Only", "scsi.feature.dvdrw.closeonly", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_dvdr_write,
          {"Write", "scsi.feature.dvdr.write", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_tao_buf,
          {"BUF", "scsi.feature.tao.buf", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_feature_tao_rwraw,
          {"R-W Raw", "scsi.feature.tao.rwraw", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_feature_tao_rwpack,
          {"R-W Pack", "scsi.feature.tao.rwpack", FT_BOOLEAN, 8,
           NULL, 0x08, "", HFILL}},
        { &hf_scsi_feature_tao_testwrite,
          {"Test Write", "scsi.feature.tao.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, "", HFILL}},
        { &hf_scsi_feature_tao_cdrw,
          {"CD-RW", "scsi.feature.tao.cdrw", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_tao_rwsubcode,
          {"R-W Subcode", "scsi.feature.tao.rwsubcode", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_dts,
          {"Data Type Supported", "scsi.feature.dts", FT_UINT16, BASE_HEX,
           NULL, 0xffff, "", HFILL}},
        { &hf_scsi_feature_sao_buf,
          {"BUF", "scsi.feature.sao.buf", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_feature_sao_sao,
          {"SAO", "scsi.feature.sao.sao", FT_BOOLEAN, 8,
           NULL, 0x20, "", HFILL}},
        { &hf_scsi_feature_sao_rawms,
          {"Raw MS", "scsi.feature.sao.rawms", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_feature_sao_raw,
          {"Raw", "scsi.feature.sao.raw", FT_BOOLEAN, 8,
           NULL, 0x08, "", HFILL}},
        { &hf_scsi_feature_sao_testwrite,
          {"Test Write", "scsi.feature.sao.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, "", HFILL}},
        { &hf_scsi_feature_sao_cdrw,
          {"CD-RW", "scsi.feature.sao.cdrw", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_sao_rw,
          {"R-W", "scsi.feature.sao.rw", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_sao_mcsl,
          {"Maximum Cue Sheet Length", "scsi.feature.sao.mcsl", FT_UINT24, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_feature_dvdr_buf,
          {"BUF", "scsi.feature.dvdr.buf", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_feature_dvdr_testwrite,
          {"Test Write", "scsi.feature.dvdr.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, "", HFILL}},
        { &hf_scsi_feature_dvdr_dvdrw,
          {"DVD-RW", "scsi.feature.dvdr.dvdrw", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_feature_profile,
          {"Profile", "scsi.feature.profile", FT_UINT16, BASE_HEX,
           VALS(scsi_getconf_current_profile_val), 0, "", HFILL}},
        { &hf_scsi_feature_profile_current,
          {"Current", "scsi.feature.profile.current", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_isw_buf,
          {"BUF", "scsi.feature.isw.buf", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_feature_isw_num_linksize,
          {"Number of Link Sizes", "scsi.feature.isw.num_linksize", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_feature_isw_linksize,
          {"Link Size", "scsi.feature.isw.linksize", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_readtoc_time,
          {"Time", "scsi.readtoc.time", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_readtoc_format,
          {"Format", "scsi.readtoc.format", FT_UINT8, BASE_HEX,
           NULL, 0x0f, "", HFILL}},
        { &hf_scsi_track,
          {"Track", "scsi.track", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_track_size,
          {"Track Size", "scsi.track_size", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_session,
          {"Session", "scsi.session", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_first_track,
          {"First Track", "scsi.first_track", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_readtoc_first_session,
          {"First Session", "scsi.readtoc.first_session", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_readtoc_last_track,
          {"Last Track", "scsi.readtoc.last_track", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_readtoc_last_session,
          {"Last Session", "scsi.readtoc.last_session", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_q_subchannel_adr,
          {"Q Subchannel ADR", "scsi.q.subchannel.adr", FT_UINT8, BASE_HEX,
           VALS(scsi_q_subchannel_adr_val), 0xf0, "", HFILL}},
        { &hf_scsi_q_subchannel_control,
          {"Q Subchannel Control", "scsi.q.subchannel.control", FT_UINT8, BASE_HEX,
           VALS(scsi_q_subchannel_control_val), 0x0f, "", HFILL}},
        { &hf_scsi_track_start_address,
          {"Track Start Address", "scsi.track_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_next_writable_address,
          {"Next Writable Address", "scsi.next_writable_address", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_track_start_time,
          {"Track Start Time", "scsi.track_start_time", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_synccache_immed,
          {"IMMED", "scsi.synccache.immed", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_synccache_reladr,
          {"RelAdr", "scsi.synccache.reladr", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_rbc_block,
          {"BLOCK", "scsi.rbc.block", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_rbc_lob_blocks,
          {"Buffer Len (blocks)", "scsi.rbc.lob_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_rbc_alob_blocks,
          {"Available Buffer Len (blocks)", "scsi.rbc.alob_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_rbc_lob_bytes,
          {"Buffer Len (bytes)", "scsi.rbc.lob_bytes", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_rbc_alob_bytes,
          {"Available Buffer Len (bytes)", "scsi.rbc.alob_bytes", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_type,
          {"Type", "scsi.setstreaming.type", FT_UINT8, BASE_DEC,
           VALS(scsi_setstreaming_type_val), 0, "", HFILL}},
        { &hf_scsi_setstreaming_param_len,
          {"Parameter Length", "scsi.setstreaming.param_len", FT_UINT16, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_wrc,
          {"WRC", "scsi.setstreaming.wrc", FT_UINT8, BASE_HEX,
           NULL, 0x18, "", HFILL}},
        { &hf_scsi_setstreaming_rdd,
          {"RDD", "scsi.setstreaming.rdd", FT_BOOLEAN, 8,
           NULL, 0x04, "", HFILL}},
        { &hf_scsi_setstreaming_exact,
          {"Exact", "scsi.setstreaming.exact", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_setstreaming_ra,
          {"RA", "scsi.setstreaming.ra", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_setstreaming_start_lba,
          {"Start LBA", "scsi.setstreaming.start_lbs", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_end_lba,
          {"End LBA", "scsi.setstreaming.end_lba", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_read_size,
          {"Read Size", "scsi.setstreaming.read_size", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_read_time,
          {"Read Time", "scsi.setstreaming.read_time", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_write_size,
          {"Write Size", "scsi.setstreaming.write_size", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_setstreaming_write_time,
          {"Write Time", "scsi.setstreaming.write_time", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_reservation_size,
          {"Reservation Size", "scsi.reservation_size", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_rti_address_type,
          {"Address Type", "scsi.rti.address_type", FT_UINT8, BASE_HEX,
           VALS(scsi_rti_address_type_val), 0x03, "", HFILL}},
        { &hf_scsi_rti_damage,
          {"Damage", "scsi.rti.damage", FT_BOOLEAN, 8,
           NULL, 0x20, "", HFILL}},
        { &hf_scsi_rti_copy,
          {"Copy", "scsi.rti.copy", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_rti_track_mode,
          {"Track Mode", "scsi.rti.track_mode", FT_UINT8, BASE_HEX,
           NULL, 0x0f, "", HFILL}},
        { &hf_scsi_rti_rt,
          {"RT", "scsi.rti.rt", FT_BOOLEAN, 8,
           NULL, 0x80, "", HFILL}},
        { &hf_scsi_rti_blank,
          {"Blank", "scsi.rti.blank", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_rti_packet,
          {"Packet/Inc", "scsi.rti.packet", FT_BOOLEAN, 8,
           NULL, 0x20, "", HFILL}},
        { &hf_scsi_rti_fp,
          {"FP", "scsi.rti.fp", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_rti_data_mode,
          {"Data Mode", "scsi.rti.data_mode", FT_UINT8, BASE_HEX,
           NULL, 0x0f, "", HFILL}},
        { &hf_scsi_rti_lra_v,
          {"LRA_V", "scsi.rti.lra_v", FT_BOOLEAN, 8,
           NULL, 0x02, "", HFILL}},
        { &hf_scsi_rti_nwa_v,
          {"NWA_V", "scsi.rti.nwa_v", FT_BOOLEAN, 8,
           NULL, 0x01, "", HFILL}},
        { &hf_scsi_free_blocks,
          {"Free Blocks", "scsi.free_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_fixed_packet_size,
          {"Fixed Packet Size", "scsi.fixed_packet_size", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_last_recorded_address,
          {"Last Recorded Address", "scsi.last_recorded_address", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_read_compatibility_lba,
          {"Read Compatibility LBA", "scsi.read_compatibility_lba", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_erasable,
          {"Erasable", "scsi.disc_info.erasable", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_disc_info_state_of_last_session,
          {"State Of Last Session", "scsi.disc_info.state_of_last_session", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_sols_val), 0x0c, "", HFILL}},
        { &hf_scsi_disc_info_disk_status,
          {"Disk Status", "scsi.disc_info.disk_status", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_disc_status_val), 0x03, "", HFILL}},
        { &hf_scsi_disc_info_number_of_sessions,
          {"Number Of Sessions", "scsi.disc_info.number_of_sessions", FT_UINT16, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_first_track_in_last_session,
          {"First Track In Last Session", "scsi.disc_info.first_track_in_last_session", FT_UINT16, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_last_track_in_last_session,
          {"Last Track In Last Session", "scsi.disc_info.last_track_in_last_session", FT_UINT16, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_did_v,
          {"DID_V", "scsi.disc_info.did_v", FT_BOOLEAN, 8,
           NULL, 0x80, "", HFILL}},
        { &hf_scsi_disc_info_dbc_v,
          {"DBC_V", "scsi.disc_info.dbc_v", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_disc_info_uru,
          {"URU", "scsi.disc_info.uru", FT_BOOLEAN, 8,
           NULL, 0x20, "", HFILL}},
        { &hf_scsi_disc_info_dac_v,
          {"DAC_V", "scsi.disc_info.dac_v", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_disc_info_dbit,
          {"Dbit", "scsi.disc_info.dbit", FT_BOOLEAN, 8,
           NULL, 0x04, "", HFILL}},
        { &hf_scsi_disc_info_bgfs,
          {"BG Format Status", "scsi.disc_info.bgfs", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_bgfs_val), 0x03, "", HFILL}},
        { &hf_scsi_disc_info_disc_type,
          {"Disc Type", "scsi.disc_info.disc_type", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_disc_type_val), 0, "", HFILL}},
        { &hf_scsi_disc_info_disc_identification,
          {"Disc Identification", "scsi.disc_info.disc_identification", FT_UINT32, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_last_session_lead_in_start_address,
          {"Last Session Lead-In Start Address", "scsi.disc_info.last_session_lead_in_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_last_possible_lead_out_start_address,
          {"Last Possible Lead-Out Start Address", "scsi.disc_info.last_possible_lead_out_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_disc_info_disc_bar_code,
          {"Disc Bar Code", "scsi.disc_info.disc_bar_code", FT_UINT64, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_sbc2_verify_lba,
          {"LBA", "scsi.sbc2.verify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_sbc2_verify_vlen,
          {"Verification Length", "scsi.sbc2.verify.vlen", FT_UINT16,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_sbc2_verify_dpo,
          {"DPO", "scsi.sbc2.verify.dpo", FT_BOOLEAN, BASE_HEX, NULL, 0x10, "",
           HFILL}},
        { &hf_sbc2_verify_blkvfy,
          {"BLKVFY", "scsi.sbc2.verify.blkvfy", FT_BOOLEAN, BASE_HEX, NULL, 0x4,
           "", HFILL}},
        { &hf_sbc2_verify_bytchk,
          {"BYTCHK", "scsi.sbc2.verify.bytchk", FT_BOOLEAN, BASE_HEX, NULL, 0x2,
           "", HFILL}},
        { &hf_sbc2_verify_reladdr,
          {"RELADDR", "scsi.sbc2.verify.reladdr", FT_BOOLEAN, BASE_HEX, NULL,
           0x1, "", HFILL}},
        { &hf_sbc2_verify_vlen32,
          {"Verification Length", "scsi.sbc2.verify.vlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_sbc2_verify_lba64,
          {"LBA", "scsi.sbc2.verify.lba64", FT_UINT64, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_sbc2_wrverify_ebp,
          {"EBP", "scsi.sbc2.wrverify.ebp", FT_BOOLEAN, BASE_HEX, NULL, 0x4, "",
           HFILL}},
        { &hf_sbc2_wrverify_lba,
          {"LBA", "scsi.sbc2.wrverify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_sbc2_wrverify_xferlen,
          {"Transfer Length", "scsi.sbc2.wrverify.xferlen", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_sbc2_wrverify_lba64,
          {"LBA", "scsi.sbc2.wrverify.lba64", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbc2_wrverify_xferlen32,
          {"Transfer Length", "scsi.sbc2.wrverify.xferlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_ssc3_space6_count,
          {"Count", "scsi.space6.count", FT_UINT24, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_ssc3_space16_count,
          {"Count", "scsi.space16.count", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_ssc3_locate10_loid,
          {"Logical Object Identifier", "scsi.locate10.loid", FT_UINT32, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_ssc3_locate16_loid,
          {"Logical Identifier", "scsi.locate16.loid", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scsi,
        &ett_scsi_page,
        &ett_scsi_profile,
    };
    module_t *scsi_module;

    /* Register the protocol name and description */
    proto_scsi = proto_register_protocol("SCSI", "SCSI", "scsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine (&scsi_init_protocol);
    data_handle = find_dissector ("data");

    /* add preferences to decode SCSI message */
    scsi_module = prefs_register_protocol (proto_scsi, NULL);
    prefs_register_enum_preference (scsi_module, "decode_scsi_messages_as",
                                    "Decode SCSI Messages As",
                                    "When Target Cannot Be Identified, Decode SCSI Messages As",
                                    &scsi_def_devtype, scsi_devtype_options, TRUE);

}
