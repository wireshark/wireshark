/* TODO make the contracts require that all functions be called with valid
 * pointers for itl and itlq and remove all tests for itl/itlq being NULL
 */
/* TODO audit value parameter for proto_tree_add_boolean() calls */
/* packet-scsi.c
 * Routines for decoding SCSI CDBs and responsess
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
 *   void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *,
 *   guint, itlq_nexus_t *, itl_nexus_t *);
 * o dissect_scsi_payload - invoked to decode SCSI responses
 *   void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *, guint,
 *                              gboolean, itlq_nexusu_t *, itl_nexus_t *,
 *                              guint32 relative_offset);
 *   The final parameter is the length of the response field that is negotiated
 *   as part of the SCSI transport layer. If this is not tracked by the
 *   transport, it can be set to 0.
 * o dissect_scsi_rsp - invoked to dissect the scsi status code in a response
 *                      SCSI task.
 *   void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *,
 *                          itlq_nexus_t *, itl_nexus_t *, guint8);
 * o dissect_scsi_snsinfo - invoked to decode the sense data provided in case of
 *                          an error.
 *   void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint,
 *   guint, itlq_nexus_t *, itl_nexus_t *);
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/reassemble.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-osd.h"
#include "packet-scsi-mmc.h"
#include "packet-scsi-sbc.h"
#include "packet-scsi-ssc.h"
#include "packet-scsi-smc.h"

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
static int hf_scsi_lun                          = -1;
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
static int hf_scsi_spcpagecode                  = -1;
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
static int hf_scsi_inq_reserved                 = -1;
static int hf_scsi_inq_version_desc             = -1;
static int hf_scsi_inq_devtype                  = -1;
static int hf_scsi_inq_rmb                      = -1;
static int hf_scsi_inq_version                  = -1;
static int hf_scsi_rluns_lun                    = -1;
static int hf_scsi_rluns_multilun               = -1;
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
static int hf_scsi_inq_reladrflags              = -1;
static int hf_scsi_inq_sync                     = -1;
static int hf_scsi_inq_reladr                   = -1;
static int hf_scsi_inq_linked                   = -1;
static int hf_scsi_inq_cmdque                   = -1;
static int hf_scsi_inq_bqueflags                = -1;
static int hf_scsi_inq_bque                     = -1;
static int hf_scsi_inq_encserv                  = -1;
static int hf_scsi_inq_multip                   = -1;
static int hf_scsi_inq_mchngr                   = -1;
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

static int scsi_tap = -1;

/* Defragment of SCSI DATA IN/OUT */
static gboolean scsi_defragment = FALSE;

static GHashTable *scsi_fragment_table = NULL;
static GHashTable *scsi_reassembled_table = NULL;

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
  fragment_table_init(&scsi_fragment_table);
  reassembled_table_init(&scsi_reassembled_table);
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
    {SCSI_SPC_ACCESS_CONTROL_IN  , "Access Control In"},
    {SCSI_SPC_ACCESS_CONTROL_OUT , "Access Control Out"},
    {SCSI_SPC_CHANGE_DEFINITION  , "Change Definition"},
    {SCSI_SPC_COMPARE            , "Compare"},
    {SCSI_SPC_COPY               , "Copy"},
    {SCSI_SPC_COPY_AND_VERIFY    , "Copy And Verify"},
    {SCSI_SPC_EXTCOPY            , "Extended Copy"},
    {SCSI_SPC_INQUIRY            , "Inquiry"},
    {SCSI_SPC_LOGSELECT          , "Log Select"},
    {SCSI_SPC_LOGSENSE           , "Log Sense"},
    {SCSI_SPC_MODESELECT6        , "Mode Select(6)"},
    {SCSI_SPC_MODESELECT10       , "Mode Select(10)"},
    {SCSI_SPC_MODESENSE6         , "Mode Sense(6)"},
    {SCSI_SPC_MODESENSE10        , "Mode Sense(10)"},
    {SCSI_SPC_PERSRESVIN         , "Persistent Reserve In"},
    {SCSI_SPC_PERSRESVOUT        , "Persistent Reserve Out"},
    {SCSI_SPC_PREVMEDREMOVAL     , "Prevent/Allow Medium Removal"},
    {SCSI_SPC_RCVCOPYRESULTS     , "Receive Copy Results"},
    {SCSI_SPC_RCVDIAGRESULTS     , "Receive Diagnostics Results"},
    {SCSI_SPC_READBUFFER         , "Read Buffer"},
    {SCSI_SPC_RELEASE6           , "Release(6)"},
    {SCSI_SPC_RELEASE10          , "Release(10)"},
    {SCSI_SPC_REPORTDEVICEID     , "Report Device ID"},
    {SCSI_SPC_REPORTLUNS         , "Report LUNs"},
    {SCSI_SPC_REQSENSE           , "Request Sense"},
    {SCSI_SPC_RESERVE6           , "Reserve(6)"},
    {SCSI_SPC_RESERVE10          , "Reserve(10)"},
    {SCSI_SPC_SENDDIAG           , "Send Diagnostic"},
    {SCSI_SPC_TESTUNITRDY        , "Test Unit Ready"},
    {SCSI_SPC_WRITEBUFFER        , "Write Buffer"},
    {SCSI_SPC_VARLENCDB          , "Variable Length CDB"},
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

static const value_string scsi_log_pc_val[] = {
    {0, "Threshold Values"},
    {1, "Cumulative Values"},
    {2, "Default Threshold Values"},
    {3, "Default Cumulative Values"},
    {0, NULL},
};

/* TapeAlert page : read warning flag */
static void
log_parameter_2e_0001(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rw, tvb, 0, 1, 0);
}

/* TapeAlert page : write warning flag */
static void
log_parameter_2e_0002(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ww, tvb, 0, 1, 0);
}

/* TapeAlert page : hard error flag */
static void
log_parameter_2e_0003(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_he, tvb, 0, 1, 0);
}

/* TapeAlert page : media flag */
static void
log_parameter_2e_0004(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_media, tvb, 0, 1, 0);
}

/* TapeAlert page : read failure flag */
static void
log_parameter_2e_0005(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rf, tvb, 0, 1, 0);
}

/* TapeAlert page : write failure flag */
static void
log_parameter_2e_0006(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wf, tvb, 0, 1, 0);
}

/* TapeAlert page : media life flag */
static void
log_parameter_2e_0007(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ml, tvb, 0, 1, 0);
}

/* TapeAlert page : not data grade flag */
static void
log_parameter_2e_0008(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ndg, tvb, 0, 1, 0);
}

/* TapeAlert page : write protect flag */
static void
log_parameter_2e_0009(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wp, tvb, 0, 1, 0);
}

/* TapeAlert page : no removal flag */
static void
log_parameter_2e_000a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nr, tvb, 0, 1, 0);
}

/* TapeAlert page : cleaning media flag */
static void
log_parameter_2e_000b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cm, tvb, 0, 1, 0);
}

/* TapeAlert page : unsupported format flag */
static void
log_parameter_2e_000c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_uf, tvb, 0, 1, 0);
}

/* TapeAlert page : removable mechanical cartridge failure flag */
static void
log_parameter_2e_000d(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rmcf, tvb, 0, 1, 0);
}

/* TapeAlert page : unrecoverable mechanical cartridge failure flag */
static void
log_parameter_2e_000e(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_umcf, tvb, 0, 1, 0);
}

/* TapeAlert page : memory chip in cartridge failure flag */
static void
log_parameter_2e_000f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_mcicf, tvb, 0, 1, 0);
}

/* TapeAlert page : forced eject flag */
static void
log_parameter_2e_0010(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_fe, tvb, 0, 1, 0);
}

/* TapeAlert page : read only format flag */
static void
log_parameter_2e_0011(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rof, tvb, 0, 1, 0);
}

/* TapeAlert page : tape directory corrupted on load flag */
static void
log_parameter_2e_0012(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tdcol, tvb, 0, 1, 0);
}

/* TapeAlert page : nearing media life flag */
static void
log_parameter_2e_0013(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nml, tvb, 0, 1, 0);
}

/* TapeAlert page : clean now flag */
static void
log_parameter_2e_0014(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cn, tvb, 0, 1, 0);
}

/* TapeAlert page : clean periodic flag */
static void
log_parameter_2e_0015(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cp, tvb, 0, 1, 0);
}

/* TapeAlert page : expired cleaning media flag */
static void
log_parameter_2e_0016(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ecm, tvb, 0, 1, 0);
}

/* TapeAlert page : invalid cleaning tape flag */
static void
log_parameter_2e_0017(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_ict, tvb, 0, 1, 0);
}

/* TapeAlert page : retention requested flag */
static void
log_parameter_2e_0018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_rr, tvb, 0, 1, 0);
}

/* TapeAlert page : dual port interface error flag */
static void
log_parameter_2e_0019(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dpie, tvb, 0, 1, 0);
}

/* TapeAlert page : cooling fan failure flag */
static void
log_parameter_2e_001a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_cff, tvb, 0, 1, 0);
}

/* TapeAlert page : power supply failure flag */
static void
log_parameter_2e_001b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_psf, tvb, 0, 1, 0);
}

/* TapeAlert page : power consumption flag */
static void
log_parameter_2e_001c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_pc, tvb, 0, 1, 0);
}

/* TapeAlert page : drive maintenance flag */
static void
log_parameter_2e_001d(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dm, tvb, 0, 1, 0);
}

/* TapeAlert page : hardware a flag */
static void
log_parameter_2e_001e(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_hwa, tvb, 0, 1, 0);
}

/* TapeAlert page : hardware b flag */
static void
log_parameter_2e_001f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_hwb, tvb, 0, 1, 0);
}

/* TapeAlert page : interface flag */
static void
log_parameter_2e_0020(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_if, tvb, 0, 1, 0);
}

/* TapeAlert page : eject media flag */
static void
log_parameter_2e_0021(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_em, tvb, 0, 1, 0);
}

/* TapeAlert page : download failed flag */
static void
log_parameter_2e_0022(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dwf, tvb, 0, 1, 0);
}

/* TapeAlert page : drive humidity flag */
static void
log_parameter_2e_0023(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drhu, tvb, 0, 1, 0);
}

/* TapeAlert page : drive temperature flag */
static void
log_parameter_2e_0024(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drtm, tvb, 0, 1, 0);
}

/* TapeAlert page : drive voltage flag */
static void
log_parameter_2e_0025(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_drvo, tvb, 0, 1, 0);
}

/* TapeAlert page : periodic failure flag */
static void
log_parameter_2e_0026(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_pefa, tvb, 0, 1, 0);
}

/* TapeAlert page : diagnostics required flag */
static void
log_parameter_2e_0027(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_dire, tvb, 0, 1, 0);
}

/* TapeAlert page : lost statistics flag */
static void
log_parameter_2e_0032(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_lost, tvb, 0, 1, 0);
}

/* TapeAlert page : tape directory invalid at unload flag */
static void
log_parameter_2e_0033(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tduau, tvb, 0, 1, 0);
}

/* TapeAlert page : tape system area write failure flag */
static void
log_parameter_2e_0034(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tsawf, tvb, 0, 1, 0);
}

/* TapeAlert page : tape system area read failure flag */
static void
log_parameter_2e_0035(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_tsarf, tvb, 0, 1, 0);
}

/* TapeAlert page : no start of data flag */
static void
log_parameter_2e_0036(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_nsod, tvb, 0, 1, 0);
}

/* TapeAlert page : loading failure flag */
static void
log_parameter_2e_0037(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_lofa, tvb, 0, 1, 0);
}

/* TapeAlert page : unrecoverable unload failure flag */
static void
log_parameter_2e_0038(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_uuf, tvb, 0, 1, 0);
}

/* TapeAlert page : automatic interface failure flag */
static void
log_parameter_2e_0039(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_aif, tvb, 0, 1, 0);
}

/* TapeAlert page : firmware failure flag */
static void
log_parameter_2e_003a(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_fwf, tvb, 0, 1, 0);
}

/* TapeAlert page : worm medium integrity check failed flag */
static void
log_parameter_2e_003b(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wmicf, tvb, 0, 1, 0);
}

/* TapeAlert page : worm medium overwrite attempted flag */
static void
log_parameter_2e_003c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_log_ta_wmoa, tvb, 0, 1, 0);
}


typedef void (*log_parameter_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef struct _log_page_parameters_t {
    guint32 number;
    char *name;
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

static const value_string scsi_persresvin_svcaction_val[] = {
    {SCSI_SPC_RESVIN_SVCA_RDKEYS, "Read Keys"},
    {SCSI_SPC_RESVIN_SVCA_RDRESV, "Read Reservation"},
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
    {"block", "Block Device", SCSI_DEV_SBC},
    {"sequential", "Sequential Device", SCSI_DEV_SSC},
    {"objectbased", "Object Based Storage Device", SCSI_DEV_OSD},
    {"mediumchanger", "Medium Changer Device", SCSI_DEV_SMC},
    {"cdrom", "Multimedia Device", SCSI_DEV_CDROM},
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
    {0x0000, "Version Descriptor Not Supported or No Standard Identified"},
    {0x0020, "SAM (no version claimed)"},
    {0x003B, "SAM T10/0994-D revision 18"},
    {0x003C, "SAM ANSI INCITS 270-1996"},
    {0x0040, "SAM-2 (no version claimed)"},
    {0x0054, "SAM-2 T10/1157-D revision 23"},
    {0x0055, "SAM-2 T10/1157-D revision 24"},
    {0x005C, "SAM-2 ANSI INCITS 366-2003"},
    {0x0060, "SAM-3 (no version claimed)"},
    {0x0062, "SAM-3 T10/1561-D revision 7"},
    {0x0075, "SAM-3 T10/1561-D revision 13"},
    {0x0076, "SAM-3 T10/1561-D revision 14"},
    {0x0077, "SAM-3 ANSI INCITS 402-200x"},
    {0x0080, "SAM-4 (no version claimed)"},
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
    {0x01C0, "SES (no version claimed)"},
    {0x01DB, "SES T10/1212-D revision 08b"},
    {0x01DC, "SES ANSI INCITS 305-1998"},
    {0x01DD, "SES T10/1212 revision 08b w/ Amendment ANSI INCITS.305/AM1-2000"},
    {0x01DE, "SES ANSI INCITS 305-1998 w/ Amendment ANSI INCITS.305/AM1-2000"},
    {0x01E0, "SCC-2 (no version claimed)"},
    {0x01FB, "SCC-2 T10/1125-D revision 04"},
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
    {0x0320, "SBC-2 (no version claimed)"},
    {0x0322, "SBC-2 T10/1417-D revision 5a"},
    {0x0324, "SBC-2 T10/1417-D revision 15"},
    {0x033B, "SBC-2 T10/1417-D revision 16"},
    {0x033D, "SBC-2 ANSI INCITS 405-200x"},
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
    {0x03BD, "MMC-4 T10/1545-D revision 3"},
    {0x03BE, "MMC-4 T10/1545-D revision 3d"},
    {0x03BF, "MMC-4 ANSI INCITS 401-200x"},
    {0x03C0, "ADC (no version claimed)"},
    {0x03D5, "ADC T10/1558-D revision 6"},
    {0x03D6, "ADC T10/1558-D revision 7"},
    {0x03D7, "ADC ANSI INCITS 403-200x"},
    {0x03E0, "SES-2 (no version claimed)"},
    {0x0400, "SSC-3 (no version claimed)"},
    {0x0420, "MMC-5 (no version claimed)"},
    {0x0440, "OSD-2 (no version claimed)"},
    {0x0460, "SPC-4 (no version claimed)"},
    {0x0480, "SMC-3 (no version claimed)"},
    {0x04A0, "ADC-2 (no version claimed)"},
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
    {0x08FB, "SBP-2 T10/1155-D revision 04"},
    {0x08FC, "SBP-2 ANSI INCITS 325-1999"},
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
    {0x09FD, "ADT ANSI INCITS 406-200x"},
    {0x0A00, "FCP-3 (no version claimed)"},
    {0x0A20, "ADT-2 (no version claimed)"},
    {0x0AA0, "SPI (no version claimed)"},
    {0x0AB9, "SPI T10/0855-D revision 15a"},
    {0x0ABA, "SPI ANSI INCITS 253-1995"},
    {0x0ABB, "SPI T10/0855-D revision 15a with SPI Amnd revision 3a"},
    {0x0ABC, "SPI ANSI INCITS 253-1995 with SPI Amnd ANSI INCITS 253/AM1-1998"},
    {0x0AC0, "Fast-20 (no version claimed)"},
    {0x0ADB, "Fast-20 T10/1071 revision 06"},
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
    {0x0BE1, "SAS T10/1562-D revision 01"},
    {0x0BF5, "SAS T10/1562-D revision 03"},
    {0x0BFA, "SAS T10/1562-D revision 04"},
    {0x0BFB, "SAS T10/1562-D revision 04"},
    {0x0BFC, "SAS T10/1562-D revision 05"},
    {0x0BFD, "SAS ANSI INCITS 376-2003"},
    {0x0C00, "SAS-1.1 (no version claimed)"},
    {0x0C07, "SAS-1.1 T10/1601-D revision 9"},
    {0x0D20, "FC-PH (no version claimed)"},
    {0x0D3B, "FC-PH ANSI INCITS 230-1994"},
    {0x0D3C, "FC-PH ANSI INCITS 230-1994 with Amnd 1 ANSI INCITS 230/AM1-1996"},
    {0x0D40, "FC-AL (no version claimed)"},
    {0x0D5C, "FC-AL ANSI INCITS 272-1996"},
    {0x0D60, "FC-AL-2 (no version claimed)"},
    {0x0D61, "FC-AL-2 T11/1133-D revision 7.0"},
    {0x0D7C, "FC-AL-2 ANSI INCITS 332-1999"},
    {0x0D7D, "FC-AL-2 ANSI INCITS 332-1999 with Amnd 1 AM1-2002"},
    {0x0D80, "FC-PH-3 (no version claimed)"},
    {0x0D9C, "FC-PH-3 ANSI INCITS 303-1998"},
    {0x0DA0, "FC-FS (no version claimed)"},
    {0x0DB7, "FC-FS T11/1331-D revision 1.2"},
    {0x0DB8, "FC-FS T11/1331-D revision 1.7"},
    {0x0DBC, "FC-FS ANSI INCITS 373-2003"},
    {0x0DC0, "FC-PI (no version claimed)"},
    {0x0DDC, "FC-PI ANSI INCITS 352-2002"},
    {0x0DE0, "FC-PI-2 (no version claimed)"},
    {0x0DE2, "FC-PI-2 T11/1506-D revision 5.0"},
    {0x0E00, "FC-FS-2 (no version claimed)"},
    {0x0E20, "FC-LS (no version claimed)"},
    {0x0E40, "FC-SP (no version claimed)"},
    {0x0E42, "FC-SP T11/1570-D revision 1.6"},
    {0x12E0, "FC-DA (no version claimed)"},
    {0x12E2, "FC-DA T11/1513-DT revision 3.1"},
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
    {0x1728, "Universal Serial Bus Specification, Revision 1.1"},
    {0x1729, "Universal Serial Bus Specification, Revision 2.0"},
    {0x1730, "USB Mass Storage Class Bulk-Only Transport, Revision 1.0"},
    {0x1EA0, "SAT (no version claimed)"},
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

const value_string scsi_devid_codeset_val[] = {
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

const value_string scsi_devid_idtype_val[] = {
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

static const true_false_string sync_tfs = {
    "Synchronous data transfer is SUPPORTED",
    "Synchronous data transfer is NOT supported",
};

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
    {0x0001,  "Filemark Detected"},
    {0x0002,  "End Of Partition/Medium Detected"},
    {0x0003,  "Setmark Detected"},
    {0x0004,  "Beginning Of Partition Detected"},
    {0x0005,  "End Of Data Detected"},    {0x0006,  "I/O Process Terminated"},
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
    "Vendor-specific Page Format",
    "Standard Page Format",
};

static gint scsi_def_devtype = SCSI_DEV_SBC;


typedef struct _cmdset_t {
    int hf_opcode;
    const value_string *cdb_vals;
    scsi_cdb_table_t *cdb_table;
} cmdset_t;

static cmdset_t *get_cmdset_data(itlq_nexus_t *itlq, itl_nexus_t *itl);

static dissector_handle_t data_handle;

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
                             val_to_str (tvb_get_guint8 (tvb, offset+1) & 0x7,
                                           scsi_cmdt_supp_val, "Unknown (%d)"));
        proto_tree_add_text (cmdt_tree, tvb, offset+2, 1, "Version: %s",
                             val_to_str_ext (tvb_get_guint8 (tvb, offset+2),
                                             &scsi_verdesc_val_ext,
                                             "Unknown (0x%02x)"));
        proto_tree_add_text (cmdt_tree, tvb, offset+5, 1, "CDB Size: %u",
                             plen);
    }
}


#define SCSI_INQ_ACAFLAGS_AERC      0x80
#define SCSI_INQ_ACAFLAGS_TRMTSK    0x40
#define SCSI_INQ_ACAFLAGS_NORMACA   0x20
#define SCSI_INQ_ACAFLAGS_HISUP     0x10

static const value_string inq_rdf_vals[] = {
    { 2, "SPC-2/SPC-3" },
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

/* This dissects byte 5 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc_inq_sccsflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    guint8 flags;
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_item(parent_tree, hf_scsi_inq_sccsflags, tvb, offset, 1, 0);
        tree = proto_item_add_subtree (item, ett_scsi_inq_sccsflags);
    }

    flags=tvb_get_guint8 (tvb, offset);

    /* SCCS (introduced in SPC-2) */
    proto_tree_add_boolean(tree, hf_scsi_inq_sccs, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_SCCSFLAGS_SCCS){
       proto_item_append_text(item, "  SCCS");
    }
    flags&=(~SCSI_INQ_SCCSFLAGS_SCCS);

    /* ACC (introduced in SPC-3) */
    proto_tree_add_boolean(tree, hf_scsi_inq_acc, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_SCCSFLAGS_ACC){
       proto_item_append_text(item, "  ACC");
    }
    flags&=(~SCSI_INQ_SCCSFLAGS_ACC);

    /* TPGS (introduced in SPC-3) */
    proto_tree_add_item (tree, hf_scsi_inq_tpgs, tvb, offset, 1, 0);
    flags&=0xcf;

    /* TPC (introduced in SPC-3) */
    proto_tree_add_boolean(tree, hf_scsi_inq_tpc, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_SCCSFLAGS_TPC){
       proto_item_append_text(item, "  3PC");
    }
    flags&=(~SCSI_INQ_SCCSFLAGS_TPC);

    /* Protect (introduced in SPC-3) */
    proto_tree_add_boolean(tree, hf_scsi_inq_protect, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_SCCSFLAGS_PROTECT){
       proto_item_append_text(item, "  PROTECT");
    }
    flags&=(~SCSI_INQ_SCCSFLAGS_PROTECT);

    offset+=1;
    return offset;
}


#define SCSI_INQ_BQUEFLAGS_BQUE     0x80
#define SCSI_INQ_BQUEFLAGS_ENCSERV  0x40
#define SCSI_INQ_BQUEFLAGS_MULTIP   0x10
#define SCSI_INQ_BQUEFLAGS_MCHNGR   0x08

/* This dissects byte 6 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc_inq_bqueflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    guint8 flags;
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_item(parent_tree, hf_scsi_inq_bqueflags, tvb, offset, 1, 0);
        tree = proto_item_add_subtree (item, ett_scsi_inq_bqueflags);
    }

    flags=tvb_get_guint8 (tvb, offset);

    /* BQUE (introduced in SPC-2) */
    proto_tree_add_boolean(tree, hf_scsi_inq_bque, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_BQUEFLAGS_BQUE){
        proto_item_append_text(item, "  BQue");
    }
    flags&=(~SCSI_INQ_BQUEFLAGS_BQUE);

    /* EncServ */
    proto_tree_add_boolean(tree, hf_scsi_inq_encserv, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_BQUEFLAGS_ENCSERV){
        proto_item_append_text(item, "  EncServ");
    }
    flags&=(~SCSI_INQ_BQUEFLAGS_ENCSERV);

    /* MultiP */
    proto_tree_add_boolean(tree, hf_scsi_inq_multip, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_BQUEFLAGS_MULTIP){
        proto_item_append_text(item, "  MultiP");
    }
    flags&=(~SCSI_INQ_BQUEFLAGS_MULTIP);

    /* MChngr */
    proto_tree_add_boolean(tree, hf_scsi_inq_mchngr, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_BQUEFLAGS_MCHNGR){
        proto_item_append_text(item, "  MChngr");
    }
    flags&=(~SCSI_INQ_BQUEFLAGS_MCHNGR);

    offset+=1;
    return offset;
}

#define SCSI_INQ_RELADRFLAGS_RELADR     0x80
#define SCSI_INQ_RELADRFLAGS_SYNC       0x10
#define SCSI_INQ_RELADRFLAGS_LINKED     0x08
#define SCSI_INQ_RELADRFLAGS_CMDQUE     0x02

/* This dissects byte 7 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc_inq_reladrflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    guint8 flags;
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_item(parent_tree, hf_scsi_inq_reladrflags, tvb, offset, 1, 0);
        tree = proto_item_add_subtree (item, ett_scsi_inq_reladrflags);
    }

    flags=tvb_get_guint8 (tvb, offset);

    /* RelAdr (obsolete in SPC-3 and later) */
    proto_tree_add_boolean(tree, hf_scsi_inq_reladr, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_RELADRFLAGS_RELADR){
        proto_item_append_text(item, "  RelAdr");
    }
    flags&=(~SCSI_INQ_RELADRFLAGS_RELADR);

    /* Sync */
    proto_tree_add_boolean(tree, hf_scsi_inq_sync, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_RELADRFLAGS_SYNC){
        proto_item_append_text(item, "  Sync");
    }
    flags&=(~SCSI_INQ_RELADRFLAGS_SYNC);

    /* Linked */
    proto_tree_add_boolean(tree, hf_scsi_inq_linked, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_RELADRFLAGS_LINKED){
        proto_item_append_text(item, "  Linked");
    }
    flags&=(~SCSI_INQ_RELADRFLAGS_LINKED);

    /* CmdQue */
    proto_tree_add_boolean(tree, hf_scsi_inq_cmdque, tvb, offset, 1, flags);
    if(flags&SCSI_INQ_RELADRFLAGS_CMDQUE){
        proto_item_append_text(item, "  CmdQue");
    }
    flags&=(~SCSI_INQ_RELADRFLAGS_CMDQUE);

    offset+=1;
    return offset;
}

void
dissect_spc_inquiry (tvbuff_t *tvb, packet_info *pinfo,
                     proto_tree *tree, guint offset, gboolean isreq,
                     gboolean iscdb, guint32 payload_len,
                     scsi_task_data_t *cdata)
{
    guint8 flags, i;
    tvbuff_t *volatile tvb_v = tvb;
    volatile guint offset_v = offset;

    static const int *inq_control_fields[] = {
        &hf_scsi_inq_control_vendor_specific,
        &hf_scsi_inq_control_reserved,
        &hf_scsi_inq_control_naca,
        &hf_scsi_inq_control_obs1,
        &hf_scsi_inq_control_obs2,
        NULL
    };
    static const int *peripheral_fields[] = {
        &hf_scsi_inq_qualifier,
            &hf_scsi_inq_devtype,
            NULL
    };
    static const int *aca_fields[] = {
        &hf_scsi_inq_aerc,      /* obsolete in spc3 and forward */
            &hf_scsi_inq_trmtsk,/* obsolete in spc2 and forward */
            &hf_scsi_inq_normaca,
            &hf_scsi_inq_hisup,
            &hf_scsi_inq_rdf,
            NULL
    };
    static const int *rmb_fields[] = {
        &hf_scsi_inq_rmb,
            NULL
    };

    if (!isreq && (cdata == NULL || !(cdata->itlq->flags & 0x3))
        && (tvb_length_remaining(tvb_v, offset_v)>=1) ) {
        /*
        * INQUIRY response with device type information; add device type
        * to list of known devices & their types if not already known.
        */
        if(cdata && cdata->itl){
            cdata->itl->cmdset=tvb_get_guint8(tvb_v, offset_v)&SCSI_DEV_BITS;
        }
    }

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb_v, offset_v);
        if (cdata) {
            cdata->itlq->flags = flags;
        }

        proto_tree_add_uint_format (tree, hf_scsi_inquiry_flags, tvb_v, offset_v, 1,
            flags, "CMDT = %u, EVPD = %u",
            flags & 0x2, flags & 0x1);
        if (flags & 0x1) {
            proto_tree_add_item (tree, hf_scsi_inquiry_evpd_page, tvb_v, offset_v+1,
                1, 0);
        }
        else if (flags & 0x2) {
            proto_tree_add_item (tree, hf_scsi_inquiry_cmdt_page, tvb_v, offset_v+1,
                1, 0);
        }

        proto_tree_add_item (tree, hf_scsi_alloclen, tvb_v, offset_v+3, 1, 0);
        /* we need the alloc_len in the response */
        if(cdata){
            cdata->itlq->alloc_len=tvb_get_guint8(tvb_v, offset_v+3);
        }
        proto_tree_add_bitmask(tree, tvb_v, offset_v+4, hf_scsi_inq_control,
            ett_scsi_inq_control, inq_control_fields, FALSE);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }

        if (cdata->itlq->flags & 0x1) {
            dissect_scsi_evpd (tvb_v, pinfo, tree, offset_v, payload_len);
            return;
        }
        if (cdata->itlq->flags & 0x2) {
            dissect_scsi_cmddt (tvb_v, pinfo, tree, offset_v, payload_len);
            return;
        }

        /* These pdus are sometimes truncated by SCSI allocation length
        * in the CDB
        */
        TRY_SCSI_CDB_ALLOC_LEN(pinfo, tvb_v, offset_v, cdata->itlq->alloc_len);

        /* Qualifier and DeviceType */
        proto_tree_add_bitmask(tree, tvb_v, offset_v, hf_scsi_inq_peripheral, ett_scsi_inq_peripheral, peripheral_fields, FALSE);
        offset_v+=1;

        /* RMB */
        proto_tree_add_bitmask(tree, tvb_v, offset_v, hf_scsi_inq_rmbflags, ett_scsi_inq_rmbflags, rmb_fields, FALSE);
        offset_v+=1;

        /* Version */
        proto_tree_add_item (tree, hf_scsi_inq_version, tvb_v, offset_v, 1, 0);
        offset_v+=1;

        /* aca flags */
        proto_tree_add_bitmask(tree, tvb_v, offset_v, hf_scsi_inq_acaflags, ett_scsi_inq_acaflags, aca_fields, FALSE);
        offset_v+=1;

        /* Additional Length */
        SET_SCSI_DATA_END(tvb_get_guint8(tvb_v, offset_v)+offset);
        proto_tree_add_item(tree, hf_scsi_inq_add_len, tvb_v, offset_v, 1, 0);
        offset_v+=1;

        /* sccs flags */
        offset_v=dissect_spc_inq_sccsflags(tvb_v, offset_v, tree);

        /* bque flags */
        offset_v=dissect_spc_inq_bqueflags(tvb_v, offset_v, tree);

        /* reladdr flags */
        offset_v=dissect_spc_inq_reladrflags(tvb_v, offset_v, tree);

        /* vendor id */
        proto_tree_add_item(tree, hf_scsi_inq_vendor_id, tvb_v, offset_v, 8, 0);
        offset_v+=8;

        /* product id */
        proto_tree_add_item(tree, hf_scsi_inq_product_id, tvb_v, offset_v, 16, 0);
        offset_v+=16;

        /* product revision level */
        proto_tree_add_item(tree, hf_scsi_inq_product_rev, tvb_v, offset_v, 4, 0);
        offset_v+=4;

        /* vendor specific, 20 bytes */
        proto_tree_add_item(tree, hf_scsi_inq_vendor_specific, tvb_v, offset_v, 20, 0);
        offset_v+=20;

        proto_tree_add_item(tree, hf_scsi_inq_reserved, tvb_v, offset_v, 2, 0);
        /* clocking, qas, ius */
        offset_v++;

        /* reserved */
        offset_v++;

        /* version descriptors */
        for(i=0;i<8;i++){
            proto_tree_add_item(tree, hf_scsi_inq_version_desc, tvb_v, offset_v, 2, 0);
            offset_v+=2;
        }

        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

void
dissect_spc_extcopy (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                     proto_tree *tree _U_, guint offset _U_,
                     gboolean isreq _U_, gboolean iscdb _U_,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

static int
dissect_scsi_log_page (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
    proto_tree *log_tree=NULL;
    proto_item *ti=NULL;
    guint old_offset=offset;
    const log_pages_t *log_page;

    pagecode=tvb_get_guint8(tvb, offset)&0x3f;

    if(tree){
        ti=proto_tree_add_text(tree, tvb, offset, -1, "Log Page: %s", val_to_str(pagecode, scsi_log_page_val, "Unknown (0x%04x)"));
        log_tree=proto_item_add_subtree(ti, ett_scsi_log);
    }

    /* page code */
    proto_tree_add_bitmask(log_tree, tvb, offset, hf_scsi_log_pc_flags, ett_scsi_log_pc, pcflags_fields, FALSE);
    offset+=1;

    /* reserved byte */
    offset+=1;

    /* page length */
    pagelen=tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(log_tree, hf_scsi_log_page_length, tvb, offset, 2, 0);
    offset+=2;


    /* find the appropriate log page */
    for(log_page=log_pages;log_page;log_page++){
        if(log_page->parameters==NULL){
            log_page=NULL;
            break;
        }
        if(log_page->page==pagecode){
            break;
        }
    }

    /* loop over all parameters */
    while( offset<(old_offset+4+pagelen) ){
        const log_page_parameters_t *log_parameter=NULL;
        guint16 log_param;

        /* parameter code */
        log_param=tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(log_tree, hf_scsi_log_parameter_code, tvb, offset, 2, 0);
        offset+=2;

        /* flags */
        proto_tree_add_bitmask(log_tree, tvb, offset, hf_scsi_log_param_flags, ett_scsi_log_param, paramflags_fields, FALSE);
        offset+=1;

        /* parameter length */
        paramlen=tvb_get_guint8(tvb, offset);
        proto_tree_add_item(log_tree, hf_scsi_log_param_len, tvb, offset, 1, 0);
        offset+=1;

        /* find the log parameter */
        if(log_page){
            for(log_parameter=log_page->parameters;log_parameter;log_parameter++){
                if(log_parameter->dissector==NULL){
                    log_parameter=NULL;
                    break;
                }
                if(log_parameter->number==log_param){
                    break;
                }
            }
        }

        /* parameter data */
        if(paramlen){
            if(log_parameter && log_parameter->dissector){
                tvbuff_t *param_tvb;

                param_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset),paramlen), paramlen);
                log_parameter->dissector(param_tvb, pinfo, log_tree);
            } else {
                /* We did not have a dissector for this page/parameter so
                 * just display it as data.
                 */
                proto_tree_add_item(log_tree, hf_scsi_log_param_data, tvb, offset, paramlen, 0);
            }
            offset+=paramlen;
        }
    }

    proto_item_set_len(ti, offset-old_offset);
    return offset;
}

void
dissect_spc_logselect (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
            ett_scsi_log_ppc, ppcflags_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_log_pc_flags, ett_scsi_log_pc, pcflags_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
dissect_spc_logsense (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
            ett_scsi_log_ppc, ppcflags_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_log_pc_flags,
            ett_scsi_log_pc, pcflags_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_log_parameter_ptr, tvb, offset+4,
            2, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }
        dissect_scsi_log_page(tvb, pinfo, tree, offset);
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
            proto_tree_add_text (scsi_tree, tvb, offset, 8, "No. of Blocks: %" G_GINT64_MODIFIER "u",
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
            if ((cdata->itl->cmdset&SCSI_CMDSET_MASK) == SCSI_DEV_SBC) {
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
                                     tvb_get_ntoh24 (tvb, offset));
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
dissect_scsi_spc_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags, proto;

    switch (pcode) {
    case SCSI_SPC_MODEPAGE_CTL:
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
                             (flags & 0x2) >> 1, (flags & 0x1));
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
    case SCSI_SPC_MODEPAGE_DISCON:
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
    case SCSI_SPC_MODEPAGE_INFOEXCP:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Perf: %u, EBF: %u, EWasc: %u, DExcpt: %u, Test: %u, LogErr: %u",
                             (flags & 0x80) >> 7, (flags & 0x20) >> 5,
                             (flags & 0x10) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x01));
        if (!((flags & 0x10) >> 4) && ((flags & 0x08) >> 3)) {
            proto_item *hidden_item;
            hidden_item = proto_tree_add_item (tree, hf_scsi_modesns_errrep, tvb,
                                        offset+3, 1, 0);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        else {
            proto_tree_add_item (tree, hf_scsi_modesns_errrep, tvb, offset+3, 1, 0);
        }
        proto_tree_add_text (tree, tvb, offset+4, 4, "Interval Timer: %u",
                             tvb_get_ntohl (tvb, offset+4));
        proto_tree_add_text (tree, tvb, offset+8, 4, "Report Count: %u",
                             tvb_get_ntohl (tvb, offset+8));
        break;
    case SCSI_SPC_MODEPAGE_PWR:
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
    case SCSI_SPC_MODEPAGE_LUN:
        return FALSE;
    case SCSI_SPC_MODEPAGE_PORT:
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
dissect_scsi_sbc_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags;

    switch (pcode) {
    case SCSI_SBC_MODEPAGE_FMTDEV:
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
    case SCSI_SBC_MODEPAGE_RDWRERR:
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
   case SCSI_SBC_MODEPAGE_DISKGEOM:
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
    case SCSI_SBC_MODEPAGE_FLEXDISK:
        return FALSE;
    case SCSI_SBC_MODEPAGE_VERERR:
        return FALSE;
    case SCSI_SBC_MODEPAGE_CACHE:
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
                             tvb_get_ntoh24 (tvb, offset+11));
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
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
            "Maximum Additional Partitions: %u",
            flags);
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
            "Additional Partitions Defined: %u",
            flags);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
            "FDP: %u, DSP: %u, IDP: %u, PSUM: %u, POFM: %u, CLEAR: %u, ADDP: %u",
            (flags & 0x80) >> 7, (flags & 0x40) >> 6,
            (flags & 0x20) >> 5, (flags & 0x18) >> 3,
            (flags & 0x04) >> 2, (flags & 0x02) >> 1,
            (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+5);
        proto_tree_add_text (tree, tvb, offset+5, 1,
            "Media Format Recognition: %u",
            flags);
        flags = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
            "Partition Units: %u",
            flags & 0x0f);
        proto_tree_add_text (tree, tvb, offset+8, 2,
            "Partition Size: %u",
            tvb_get_ntohs (tvb, offset+8));
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
dissect_scsi_mmc5_modepage (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                            proto_tree *tree _U_, guint offset _U_, guint8 pcode)
{
    guint8 flags;
    guint8 i;
    guint16 n;

    switch (pcode) {
    case SCSI_MMC5_MODEPAGE_MRW:
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "LBA Space: %u",
                             (flags & 0x01));
        break;
    case SCSI_MMC5_MODEPAGE_WRPARAM:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "BUFE: %u, LS_V: %u, Test Write: %u, Write Type: %u",
                             (flags & 0x40) >> 6, (flags & 0x20) >> 5, (flags & 0x10) >> 4, (flags & 0x0f));
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Multi-session: %u, FP: %u, Copy: %u, Track Mode: %u",
                             (flags & 0xc0) >> 6, (flags & 0x20) >> 5, (flags & 0x10) >> 4, (flags & 0x0f));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "Data Block Type: %u",
                             (flags & 0x0f));
        flags = tvb_get_guint8 (tvb, offset+5);
        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "Link Size: %u",
                             flags);
        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "Initiator Application Code: %u",
                             (flags & 0x3f));
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_text (tree, tvb, offset+8, 1,
                             "Session Format: %u",
                             flags);
        proto_tree_add_text (tree, tvb, offset+10, 4,
                             "Packet Size: %u",
                             tvb_get_ntohl (tvb, offset+10));
        proto_tree_add_text (tree, tvb, offset+14, 2,
                             "Audio Pause Length: %u",
                             tvb_get_ntohs (tvb, offset+14));
        proto_tree_add_text (tree, tvb, offset+16, 16,
                             "Media Catalog Number: %s",
                             tvb_format_stringzpad (tvb, offset+16, 16));
        proto_tree_add_text (tree, tvb, offset+32, 16,
                             "International Standard Recording Code: %s",
                             tvb_format_stringzpad (tvb, offset+32, 16));
        for (i = 0; i < 4; i++) {
            flags = tvb_get_guint8 (tvb, offset+48+i);
            proto_tree_add_text (tree, tvb, offset+48+i, 1,
                                 "Sub-header Byte %u: %u",
                                 i, flags);
        }
        if (0x36 == tvb_get_guint8 (tvb, offset+1))
            proto_tree_add_text (tree, tvb, offset+52, 4,
                                 "Vendor Specific: %u",
                                 tvb_get_ntohl (tvb, offset+52));
        break;
    case SCSI_MMC3_MODEPAGE_MMCAP:
        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "DVD-RAM Read: %u, DVD-R Read: %u, DVD-ROM Read: %u,"
                             "Method 2: %u, CD-RW Read: %u, CD-R Read: %u",
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "DVD-RAM Write: %u, DVD-R Write: %u, DVD-ROM Write: %u,"
                             "Test Write: %u, CD-RW Write: %u, CD-R Write: %u",
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 1,
                             "BUF: %u, Multi Session: %u, Mode 2 Form 2: %u, Mode 2 Form 1: %u,"
                             "Digital Port (2): %u, Digital Port (1): %u, Composite: %u, Audio Play: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6, (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+5);
        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "Read Bar Code: %u, UPC: %u, ISRC: %u, C2 Pointers supported: %u,"
                             "R-W Deinterleaved & corrected: %u, R-W Supported: %u, CD-DA Stream is Accurate: %u, CD-DA Cmds Supported: %u",
                             (flags & 0x80) >> 7, (flags & 0x40) >> 6, (flags & 0x20) >> 5, (flags & 0x10) >> 4,
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "Loading Mechanism Type: %u, Eject: %u, Prevent Jumper: %u,"
                             "Lock State: %u, Lock: %u",
                             (flags & 0xe0) >> 5, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "R-W in Lead-in: %u, Side Change Capable: %u, S/W Slot Selection: %u,"
                             "Changer Supports Disc Present: %u, Separate Channel Mute: %u, Separate volume levels: %u",
                             (flags & 0x20) >> 5, (flags & 0x10) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1, (flags & 0x01));
        proto_tree_add_text (tree, tvb, offset+10, 2,
                             "Number of Volume Levels Supported: %u",
                             tvb_get_ntohs (tvb, offset+10));
        proto_tree_add_text (tree, tvb, offset+12, 2,
                             "Buffer Size Supported: %u",
                             tvb_get_ntohs (tvb, offset+12));
        flags = tvb_get_guint8 (tvb, offset+17);
        proto_tree_add_text (tree, tvb, offset+17, 1,
                             "Length: %u, LSBF: %u, RCK: %u, BCKF: %u",
                             (flags & 0x30) >> 4, (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2, (flags & 0x02) >> 1);
        proto_tree_add_text (tree, tvb, offset+22, 2,
                             "Copy Management Revision Support: %u",
                             tvb_get_ntohs (tvb, offset+22));
        flags = tvb_get_guint8 (tvb, offset+27);
        proto_tree_add_text (tree, tvb, offset+27, 1,
                             "Rotation Control Selected: %u",
                             (flags & 0x03));
        proto_tree_add_text (tree, tvb, offset+28, 2,
                             "Current Write Speed Selected: %u",
                             tvb_get_ntohs (tvb, offset+28));
        n = tvb_get_ntohs (tvb, offset+30);
        proto_tree_add_text (tree, tvb, offset+30, 2,
                             "Number of Logical Unit Write Speed Performance Descriptor Tables: %u",
                             n);
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

static gboolean
dissect_scsi_smc_modepage (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, guint8 pcode)
{
    guint8 flags;
    guint8 param_list_len;

    switch (pcode) {
    case SCSI_SMC_MODEPAGE_EAA:
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
    case SCSI_SMC_MODEPAGE_TRANGEOM:
        return FALSE;
    case SCSI_SMC_MODEPAGE_DEVCAP:
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
             * (it failed in "match_strval()"), so it'll return
             * "Unknown (XXX)", which is what we want.
             */
            modepage_val = scsi_spc_modepage_val;
            hf_pagecode = hf_scsi_spcpagecode;
            dissect_modepage = dissect_scsi_spc_modepage;
            break;
        }
    } else {
        modepage_val = scsi_spc_modepage_val;
        hf_pagecode = hf_scsi_spcpagecode;
        dissect_modepage = dissect_scsi_spc_modepage;
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

void
dissect_spc_modeselect6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
        switch (cdata->itl->cmdset&SCSI_CMDSET_MASK) {

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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            payload_len -= plen;
        }
    }
}

void
dissect_spc_modeselect10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
        if(!cdata->itl)
            return;
        switch (cdata->itl->cmdset&SCSI_CMDSET_MASK) {

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
        offset += 2;    /* skip LongLBA byte and reserved byte */
        payload_len -= 2;

        if (payload_len < 1)
            return;
        desclen = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2,
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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
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
    int hf_pagecode;

    /* unless we have cdata there is not much point in continuing */
    if (!cdata)
        return;

    pcode = tvb_get_guint8 (tvb, offset);
    if (match_strval (pcode & SCSI_MS_PCODE_BITS,
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
            hf_pagecode = hf_scsi_spcpagecode;
            break;
        }
    } else {
        hf_pagecode = hf_scsi_spcpagecode;
    }
    proto_tree_add_uint (tree, hf_pagecode, tvb, offset, 1, pcode);
}

void
dissect_spc_modesense6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
dissect_spc_modesense10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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
        offset += 2;    /* skip LongLBA byte and reserved byte */
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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
dissect_spc_preventallowmediaremoval (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
dissect_spc_persistentreservein (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len, scsi_task_data_t *cdata)
{
    guint16 flags;
    int numrec, i;
    guint len;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_persresvin_svcaction, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, 0);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
        /* We store the service action since we want to interpret the data */
        cdata->itlq->flags = tvb_get_guint8 (tvb, offset);
    }
    else {
        if (cdata) {
            flags = cdata->itlq->flags;
        }
        else {
            flags = 0xFF;
        }
        proto_tree_add_text (tree, tvb, offset, 4, "Generation Number: 0x%08x",
                             tvb_get_ntohl (tvb, offset));
        len = tvb_get_ntohl (tvb, offset+4);
        proto_tree_add_text (tree, tvb, offset+4, 4, "Additional Length: %u",
                             len);
        len = (payload_len > len) ? len : payload_len;

        if ((flags & 0x1F) == SCSI_SPC_RESVIN_SVCA_RDKEYS) {
            /* XXX - what if len is < 8?  That may be illegal, but
               that doesn't make it impossible.... */
            numrec = len / 8;
            offset += 8;

            for (i = 0; i < numrec; i++) {
                proto_tree_add_item (tree, hf_scsi_persresv_key, tvb, offset,
                                     8, 0);
                offset += 8;
            }
        }
        else if ((flags & 0x1F) == SCSI_SPC_RESVIN_SVCA_RDRESV) {
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

void
dissect_spc_persistentreserveout (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_persresvout_svcaction, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_persresv_scope, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_persresv_type, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_paramlen16, tvb, offset+6, 2, 0);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
        /* We store the service action since we want to interpret the params */
        cdata->itlq->flags = tvb_get_guint8 (tvb, offset);
    }
    else if (isreq && !iscdb) {
        proto_tree_add_item (tree, hf_scsi_persresvout_reskey, tvb, offset,
                             8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_persresvout_sareskey, tvb,
                             offset +8, 8, ENC_NA);
        if (cdata->itlq->flags == 0x07) {
            const int *persresv_fields[] = {
                &hf_scsi_persresv_control_rsvd,
                &hf_scsi_persresv_control_unreg,
                &hf_scsi_persresv_control_aptpl,
                NULL
            };
            proto_tree_add_item (tree, hf_scsi_persresvout_obsolete, tvb,
                                 offset+16, 1, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, offset+17,
                hf_scsi_persresvout_control, ett_persresv_control,
                persresv_fields, FALSE);
        }
        else {
            const int *persresv_fields[] = {
                &hf_scsi_persresv_control_rsvd1,
                &hf_scsi_persresv_control_spec_i_pt,
                &hf_scsi_persresv_control_all_tg_pt,
                &hf_scsi_persresv_control_rsvd2,
                &hf_scsi_persresv_control_aptpl,
                NULL
            };

            proto_tree_add_item (tree, hf_scsi_persresvout_obsolete, tvb,
                                 offset+16, 4, ENC_NA);
            proto_tree_add_bitmask(tree, tvb, offset+20,
                hf_scsi_persresvout_control, ett_persresv_control,
                persresv_fields, FALSE);
        }
    }
    else {
    }
}

void
dissect_spc_release6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
dissect_spc_release10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_spc_reportdeviceidentifier (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
proto_tree *tree _U_,
                  guint offset _U_, gboolean isreq _U_, gboolean iscdb _U_,
                  guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

void
dissect_spc_reportluns (tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *tree, guint offset,
                        gboolean isreq, gboolean iscdb, guint payload_len _U_,
                        scsi_task_data_t *cdata _U_)
{
    gint listlen;
    tvbuff_t *volatile tvb_v = tvb;
    volatile guint offset_v = offset;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_select_report, tvb_v, offset_v+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb_v, offset_v+5, 4, 0);
        if(cdata){
            cdata->itlq->alloc_len=tvb_get_ntohl(tvb_v, offset_v+5);
        }
        proto_tree_add_bitmask(tree, tvb, offset_v+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    } else if (!isreq) {
        if (!cdata) {
            return;
        }

        TRY_SCSI_CDB_ALLOC_LEN(pinfo, tvb_v, offset_v, cdata->itlq->alloc_len);
        listlen = tvb_get_ntohl(tvb_v, offset_v);
        proto_tree_add_text (tree, tvb_v, offset_v, 4, "LUN List Length: %u",
                             listlen);
        offset_v += 8;

        while(listlen>0){
            if (!tvb_get_guint8 (tvb_v, offset_v))
                proto_tree_add_item (tree, hf_scsi_rluns_lun, tvb_v, offset_v+1, 1,
                                     0);
            else
                proto_tree_add_item (tree, hf_scsi_rluns_multilun, tvb_v, offset_v,
                                     8, 0);
            offset_v+=8;
            listlen-=8;
        }
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

static void
dissect_scsi_fix_snsinfo (tvbuff_t *tvb, proto_tree *sns_tree, guint offset)
{
    proto_item *hidden_item;
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
    hidden_item = proto_tree_add_item (sns_tree, hf_scsi_asc, tvb, offset+12, 1, 0);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item (sns_tree, hf_scsi_ascq, tvb, offset+13, 1, 0);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_item (sns_tree, hf_scsi_fru, tvb, offset+14, 1, 0);
    proto_tree_add_item (sns_tree, hf_scsi_sksv, tvb, offset+15, 1, 0);
    proto_tree_add_text (sns_tree, tvb, offset+15, 3,
                             "Sense Key Specific: %s",
                             tvb_bytes_to_str (tvb, offset+15, 3));
}

void
dissect_spc_requestsense (tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_alloclen, tvb, offset+3, 1, 0);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
    else if (!isreq)
        dissect_scsi_fix_snsinfo(tvb, tree, offset);
}

void
dissect_spc_reserve6 (tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
dissect_spc_reserve10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

void
dissect_spc_testunitready (tvbuff_t * tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}






void
dissect_spc_senddiagnostic (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb _U_,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree && !isreq)
        return;

    proto_tree_add_uint (tree, hf_scsi_senddiag_st_code, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_pf, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_st, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_devoff, tvb, offset, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_senddiag_unitoff, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_paramlen16, tvb, offset+2, 2, 0);
    proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
        ett_scsi_control, cdb_control_fields, FALSE);
}

void
dissect_spc_writebuffer (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb _U_,
                          guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree && !isreq)
        return;

    proto_tree_add_uint (tree, hf_scsi_wb_mode, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_wb_bufferid, tvb, offset+1, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_wb_bufoffset, tvb, offset+2, 3, 0);
    proto_tree_add_uint (tree, hf_scsi_paramlen24, tvb, offset+5, 3, 0);
    proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
        ett_scsi_control, cdb_control_fields, FALSE);
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

void
dissect_scsi_rsp (tvbuff_t *tvb, packet_info *pinfo,
                  proto_tree *tree, itlq_nexus_t *itlq, itl_nexus_t *itl,
                  guint8 scsi_status)
{
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    cmdset_t *csdata;
    scsi_task_data_t *cdata;

    cdata = ep_alloc(sizeof(scsi_task_data_t));
    cdata->itl=itl;
    cdata->itlq=itlq;
    cdata->type=SCSI_PDU_TYPE_RSP;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    csdata=get_cmdset_data(itlq, itl);   /* will g_assert if itlq is null */

    /* Nothing really to do here, just print some stuff passed to us
     */
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, 0,
                                             0, "SCSI Response (%s)",
                                             val_to_str (itlq->scsi_opcode,
                                                         csdata->cdb_vals,
                                                         "CDB:0x%02x"));
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);
    }

    ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);


    if(itl){
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
        PROTO_ITEM_SET_GENERATED(ti);

        if(itlq->scsi_opcode!=0xffff){
            ti=proto_tree_add_uint(scsi_tree, csdata->hf_opcode, tvb, 0, 0, itlq->scsi_opcode);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    if(itlq->first_exchange_frame){
        nstime_t delta_time;
        ti=proto_tree_add_uint(scsi_tree, hf_scsi_request_frame, tvb, 0, 0, itlq->first_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
        nstime_delta(&delta_time, &pinfo->fd->abs_ts, &itlq->fc_time);
        ti=proto_tree_add_time(scsi_tree, hf_scsi_time, tvb, 0, 0, &delta_time);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti=proto_tree_add_uint(scsi_tree, hf_scsi_status, tvb, 0, 0, scsi_status);
    PROTO_ITEM_SET_GENERATED(ti);
    if (check_col (pinfo->cinfo, COL_INFO)) {
         col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI: Response LUN: 0x%02x (%s) (%s)", itlq->lun,
             val_to_str(itlq->scsi_opcode, csdata->cdb_vals, "CDB:0x%02x"),
             val_to_str(scsi_status, scsi_status_val, "Unknown (0x%08x)"));

         col_set_fence(pinfo->cinfo, COL_INFO);
     }

}

void
dissect_scsi_snsinfo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, guint snslen, itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    proto_item *ti;
    proto_tree *sns_tree=NULL;
    const char *old_proto;
    scsi_task_data_t *cdata;

    cdata = ep_alloc(sizeof(scsi_task_data_t));
    cdata->itl=itl;
    cdata->itlq=itlq;
    cdata->type=SCSI_PDU_TYPE_SNS;
    tap_queue_packet(scsi_tap, pinfo, cdata);


    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                             snslen, "SCSI: SNS Info");
        sns_tree = proto_item_add_subtree (ti, ett_scsi);
    }


    ti=proto_tree_add_uint(sns_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);
    if (check_col (pinfo->cinfo, COL_INFO)) {
         col_append_fstr (pinfo->cinfo, COL_INFO, " LUN:0x%02x ", itlq->lun);

         col_set_fence(pinfo->cinfo, COL_INFO);
    }

    dissect_scsi_fix_snsinfo (tvb, sns_tree, offset);

    pinfo->current_proto=old_proto;
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
dissect_scsi_cdb (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  gint devtype_arg _U_, itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode;
#if 0
    scsi_device_type devtype;
#endif
    const gchar *valstr;
    scsi_task_data_t *cdata;
    const char *old_proto;
    cmdset_t *csdata;


    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    if(!itlq){
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    if(!itl){
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    opcode = tvb_get_guint8 (tvb, offset);
    itlq->scsi_opcode=opcode;
    csdata=get_cmdset_data(itlq, itl);

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

    if ((valstr = match_strval (opcode, scsi_spc_vals)) == NULL) {
        valstr = match_strval(opcode, csdata->cdb_vals);
    }

    if (check_col (pinfo->cinfo, COL_INFO)) {
        if (valstr != NULL) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI: %s LUN: 0x%02x ", valstr, itlq->lun);
        } else {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI Command: 0x%02x LUN:0x%02x ", opcode, itlq->lun);
        }
        /* make sure no one will overwrite this in the info column */
        col_set_fence(pinfo->cinfo, COL_INFO);
    }

    cdata = ep_alloc(sizeof(scsi_task_data_t));
    cdata->itl=itl;
    cdata->itlq=itlq;
    cdata->type=SCSI_PDU_TYPE_CDB;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, 0,
                                             -1, "SCSI CDB %s",
                                             val_to_str (opcode,
                                                         csdata->cdb_vals,
                                                         "0x%02x")
                                             );
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);
    }

    ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);

    if(itl){
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if(itlq->last_exchange_frame){
        ti=proto_tree_add_uint(scsi_tree, hf_scsi_response_frame, tvb, 0, 0, itlq->last_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    if (valstr != NULL) {
        proto_tree_add_uint_format (scsi_tree, csdata->hf_opcode, tvb,
                                    offset, 1,
                                    tvb_get_guint8 (tvb, offset),
                                    "Opcode: %s (0x%02x)", valstr,
                                    opcode);
    } else {
        proto_tree_add_item (scsi_tree, hf_scsi_spcopcode, tvb, offset, 1, 0);
    }

    if(csdata->cdb_table[opcode].func){
        csdata->cdb_table[opcode].func(tvb, pinfo, scsi_tree, offset+1,
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
                      gboolean isreq, itlq_nexus_t *itlq, itl_nexus_t *itl,
                      guint32 relative_offset)
{
    int offset=0;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode;
    scsi_task_data_t *cdata;
    int payload_len;
    const char *old_proto;
    cmdset_t *csdata;
    guint32 expected_length;
    fragment_data *ipfd_head;
    tvbuff_t *next_tvb=tvb;
    gboolean   update_col_info = TRUE, more_frags = FALSE;

    if(!itlq || !itl){
        /* we have no record of this exchange and so we can't dissect the
         * payload
         */
         proto_tree_add_text(tree, tvb, offset, 0, "Unknown SCSI exchange, can not decode SCSI data");
        return;
    }

    payload_len=tvb_length(tvb);
    cdata = ep_alloc(sizeof(scsi_task_data_t));
    cdata->itl=itl;
    cdata->itlq=itlq;
    cdata->type=SCSI_PDU_TYPE_CDB;
    tap_queue_packet(scsi_tap, pinfo, cdata);

    csdata=get_cmdset_data(itlq, itl);

    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    opcode = (guint8) cdata->itlq->scsi_opcode;

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                             payload_len,
                                             "SCSI Payload (%s %s)",
                                             val_to_str (opcode,
                                                         csdata->cdb_vals,
                                                         "CDB:0x%02x"),
                                             isreq ? "Request Data" : "Response Data");
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);
    }

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_add_fstr (pinfo->cinfo, COL_INFO,
            "SCSI: Data %s LUN: 0x%02x (%s %s) ",
            isreq ? "Out" : "In",
            itlq->lun,
            val_to_str (opcode, csdata->cdb_vals, "0x%02x"),
            isreq ? "Request Data" : "Response Data");

        col_set_fence(pinfo->cinfo, COL_INFO);
    }


    ti=proto_tree_add_uint(scsi_tree, hf_scsi_lun, tvb, 0, 0, itlq->lun);
    PROTO_ITEM_SET_GENERATED(ti);

    if(itl){
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown (%d)"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
        PROTO_ITEM_SET_GENERATED(ti);

        if(itlq && itlq->scsi_opcode!=0xffff){
            ti=proto_tree_add_uint(scsi_tree, csdata->hf_opcode, tvb, 0, 0, itlq->scsi_opcode);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    if(itlq->first_exchange_frame){
        ti=proto_tree_add_uint(scsi_tree, hf_scsi_request_frame, tvb, 0, 0, itlq->first_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if(itlq->last_exchange_frame){
        ti=proto_tree_add_uint(scsi_tree, hf_scsi_response_frame, tvb, 0, 0, itlq->last_exchange_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* If we dont know the CDB opcode there is no point in trying to
     * dissect the data.
     */
    if( !itlq->first_exchange_frame ){
        call_dissector (data_handle, tvb, pinfo, scsi_tree);
        goto end_of_payload;
    }

    /* If we are not doing data reassembly we only call the dissector
     * for the very first data in/out pdu in each transfer
     */
    if (!scsi_defragment) {
        if (relative_offset) {
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
            goto end_of_payload;
        } else {
            goto dissect_the_payload;
        }
    }

    /* If we dont have the entire PDU there is no point in even trying
     * reassembly
     */
    if(tvb_length_remaining(tvb, offset)!=tvb_reported_length_remaining(tvb, offset)){
        if (relative_offset) {
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
            goto end_of_payload;
        } else {
            goto dissect_the_payload;
        }
    }


    /* What is the expected data length for this transfer */
    if( (itlq->task_flags&(SCSI_DATA_READ|SCSI_DATA_WRITE))==(SCSI_DATA_READ|SCSI_DATA_WRITE) ){
        /* This is a bidirectional transfer */
        if(isreq){
            expected_length=itlq->data_length;
        } else {
            expected_length=itlq->bidir_data_length;
        }
    } else {
        /* This is a unidirectional transfer */
        expected_length=itlq->data_length;
    }

    /* If this PDU already contains all the expected data we dont have to do
     * reassembly.
     */
    if( (!relative_offset) && ((guint32)tvb_length_remaining(tvb, offset) == expected_length) ){
        goto dissect_the_payload;
    }


    /* Start reassembly */

    if (tvb_length_remaining(tvb, offset) < 0) {
        goto end_of_payload;
    }
    if ((tvb_length_remaining(tvb,offset) + relative_offset) != expected_length) {
        more_frags = TRUE;
    }
    ipfd_head = fragment_add_check(tvb, offset, pinfo,
                             itlq->first_exchange_frame, /* key */
                             scsi_fragment_table,
                             scsi_reassembled_table,
                             relative_offset,
                             tvb_length_remaining(tvb, offset),
                             more_frags);
    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled SCSI DATA", ipfd_head, &scsi_frag_items, &update_col_info, tree);

    if( ipfd_head && ipfd_head->reassembled_in != pinfo->fd->num ){
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "[Reassembled in #%u] ",
              ipfd_head->reassembled_in);
        }
    }


dissect_the_payload:
    if(!next_tvb){
        /* reassembly has not yet finished so we dont have a tvb yet */
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
            dissect_spc_inquiry (next_tvb, pinfo, scsi_tree, offset, isreq,
                                  FALSE, payload_len, cdata);
        }
    } else {
        /*
           All commandsets support SPC?
        */
        if(csdata->cdb_table && (csdata->cdb_table)[opcode].func){
            (csdata->cdb_table)[opcode].func(next_tvb, pinfo, scsi_tree, offset,
                               isreq, FALSE, payload_len, cdata);
        } else if(spc[opcode].func){
            spc[opcode].func(next_tvb, pinfo, scsi_tree, offset,
                               isreq, FALSE, payload_len, cdata);
        } else { /* dont know this CDB */
            call_dissector (data_handle, next_tvb, pinfo, scsi_tree);
        }
    }

end_of_payload:
    pinfo->current_proto=old_proto;
}

static cmdset_t *
get_cmdset_data(itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    cmdset_t *csdata;
    guint8 cmdset;

    /* we must have an itlq structure */
    if(!itlq){
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    if(itl){
        if(itl->cmdset==0xff){
            itl->cmdset=scsi_def_devtype|SCSI_CMDSET_DEFAULT;
        }
        cmdset=itl->cmdset;
    } else {
        cmdset=scsi_def_devtype;
    }

    csdata=ep_alloc(sizeof(cmdset_t));

    switch(cmdset&SCSI_CMDSET_MASK){
    case SCSI_DEV_SBC:
        csdata->hf_opcode=hf_scsi_sbc_opcode;
        csdata->cdb_vals=scsi_sbc_vals;
        csdata->cdb_table=scsi_sbc_table;
        break;
    case SCSI_DEV_CDROM:
        csdata->hf_opcode=hf_scsi_mmc_opcode;
        csdata->cdb_vals=scsi_mmc_vals;
        csdata->cdb_table=scsi_mmc_table;
        break;
    case SCSI_DEV_SSC:
        csdata->hf_opcode=hf_scsi_ssc_opcode;
        csdata->cdb_vals=scsi_ssc_vals;
        csdata->cdb_table=scsi_ssc_table;
        break;
    case SCSI_DEV_SMC:
        csdata->hf_opcode=hf_scsi_smc_opcode;
        csdata->cdb_vals=scsi_smc_vals;
        csdata->cdb_table=scsi_smc_table;
        break;
    case SCSI_DEV_OSD:
        csdata->hf_opcode=hf_scsi_osd_opcode;
        csdata->cdb_vals=scsi_osd_vals;
        csdata->cdb_table=scsi_osd_table;
        break;
    default:
        csdata->hf_opcode=hf_scsi_spcopcode;
        csdata->cdb_vals=scsi_spc_vals;
        csdata->cdb_table=spc;
        break;
    }

    return csdata;
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
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_status,
          { "Status", "scsi.status", FT_UINT8, BASE_HEX,
           VALS(scsi_status_val), 0, "SCSI command status value", HFILL }},
        { &hf_scsi_spcopcode,
          {"SPC-2 Opcode", "scsi.spc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc_vals), 0x0, NULL, HFILL}},
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
           VALS (scsi_evpd_pagecode_val), 0x0, NULL, HFILL}},
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
           VALS (scsi_log_pc_val), 0xC0, NULL, HFILL}},
        { &hf_scsi_log_pagecode,
          {"Page Code", "scsi.log.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_log_page_val), 0x3F, NULL, HFILL}},
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
           VALS (scsi_modesns_pc_val), 0xC0, NULL, HFILL}},
        { &hf_scsi_spcpagecode,
          {"SPC-2 Page Code", "scsi.mode.spc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_sbcpagecode,
          {"SBC-2 Page Code", "scsi.mode.sbc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_sscpagecode,
          {"SSC-2 Page Code", "scsi.mode.ssc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_ssc2_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_mmcpagecode,
          {"MMC-5 Page Code", "scsi.mode.mmc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_mmc5_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_smcpagecode,
          {"SMC-2 Page Code", "scsi.mode.smc.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_smc_modepage_val), 0x3F, NULL, HFILL}},
        { &hf_scsi_modesns_flags,
          {"Mode Sense Flags", "scsi.mode.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_persresvin_svcaction,
          {"Service Action", "scsi.persresvin.svcaction", FT_UINT8, BASE_HEX,
           VALS (scsi_persresvin_svcaction_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_persresvout_svcaction,
          {"Service Action", "scsi.persresvout.svcaction", FT_UINT8, BASE_HEX,
           VALS (scsi_persresvout_svcaction_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_persresv_scope,
          {"Reservation Scope", "scsi.persresv.scope", FT_UINT8, BASE_HEX,
           VALS (scsi_persresv_scope_val), 0xF0, NULL, HFILL}},
        { &hf_scsi_persresv_type,
          {"Reservation Type", "scsi.persresv.type", FT_UINT8, BASE_HEX,
           VALS (scsi_persresv_type_val), 0x0F, NULL, HFILL}},
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
        { &hf_scsi_persresv_control_rsvd,
          {"Reserved", "scsi.persresv.control.reserved", FT_UINT8, BASE_HEX,
           NULL, 0xFC, NULL, HFILL}},
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
           VALS (scsi_qualifier_val), 0xE0, NULL, HFILL}},
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
        { &hf_scsi_inq_reserved,
          {"Reserved", "scsi.inquiry.reserved", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_inq_version_desc,
          {"Version Description", "scsi.inquiry.version_desc", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
           &scsi_verdesc_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_inq_devtype,
          {"Device Type", "scsi.inquiry.devtype", FT_UINT8, BASE_HEX,
           VALS (scsi_devtype_val), SCSI_DEV_BITS, NULL, HFILL}},
        { &hf_scsi_inq_rmb,
          {"Removable", "scsi.inquiry.removable", FT_BOOLEAN, 8,
           TFS (&scsi_removable_val), 0x80, NULL, HFILL}},
        { & hf_scsi_inq_version,
          {"Version", "scsi.inquiry.version", FT_UINT8, BASE_HEX,
           VALS (scsi_inquiry_vers_val), 0x0, NULL, HFILL}},
        { &hf_scsi_inq_reladrflags,
          {"Inquiry RelAdr Flags", "scsi.inquiry.reladrflags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_inq_reladr,
          {"RelAdr", "scsi.inquiry.reladr", FT_BOOLEAN, 8, TFS(&reladr_tfs), SCSI_INQ_RELADRFLAGS_RELADR,
           NULL, HFILL}},
        { &hf_scsi_inq_sync,
          {"Sync", "scsi.inquiry.sync", FT_BOOLEAN, 8, TFS(&sync_tfs), SCSI_INQ_RELADRFLAGS_SYNC,
           NULL, HFILL}},
        { &hf_scsi_inq_linked,
          {"Linked", "scsi.inquiry.linked", FT_BOOLEAN, 8, TFS(&linked_tfs), SCSI_INQ_RELADRFLAGS_LINKED,
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
        { &hf_scsi_rluns_lun,
          {"LUN", "scsi.reportluns.lun", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_rluns_multilun,
          {"Multi-level LUN", "scsi.reportluns.mlun", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_modesns_errrep,
          {"MRIE", "scsi.mode.mrie", FT_UINT8, BASE_HEX,
           VALS (scsi_modesns_mrie_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_modesns_tst,
          {"Task Set Type", "scsi.mode.tst", FT_UINT8, BASE_DEC,
           VALS (scsi_modesns_tst_val), 0xE0, NULL, HFILL}},
        { &hf_scsi_modesns_qmod,
          {"Queue Algorithm Modifier", "scsi.mode.qmod", FT_UINT8, BASE_HEX,
           VALS (scsi_modesns_qmod_val), 0xF0, NULL, HFILL}},
        { &hf_scsi_modesns_qerr,
          {"Queue Error Management", "scsi.mode.qerr", FT_BOOLEAN, 8,
           TFS (&scsi_modesns_qerr_val), 0x2, NULL, HFILL}},
        { &hf_scsi_modesns_tas,
          {"Task Aborted Status", "scsi.mode.tac", FT_BOOLEAN, 8,
           TFS (&scsi_modesns_tas_val), 0x80, NULL, HFILL}},
        { &hf_scsi_modesns_rac,
          {"Report a Check", "scsi.mode.rac", FT_BOOLEAN, 8,
           TFS (&scsi_modesns_rac_val), 0x40, NULL, HFILL}},
        { &hf_scsi_protocol,
          {"Protocol", "scsi.proto", FT_UINT8, BASE_DEC, VALS (scsi_proto_val),
           0x0F, NULL, HFILL}},
        { &hf_scsi_sns_errtype,
          {"SNS Error Type", "scsi.sns.errtype", FT_UINT8, BASE_HEX,
           VALS (scsi_sns_errtype_val), 0x7F, NULL, HFILL}},
        { &hf_scsi_snskey,
          {"Sense Key", "scsi.sns.key", FT_UINT8, BASE_HEX,
           VALS (scsi_sensekey_val), 0x0F, NULL, HFILL}},
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
           VALS (scsi_wb_mode_val), 0xF, NULL, HFILL}},
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
           VALS (scsi_senddiag_st_code_val), 0xE0, NULL, HFILL}},
        { &hf_scsi_select_report,
          {"Select Report", "scsi.spc.select_report", FT_UINT8, BASE_HEX,
           VALS (scsi_select_report_val), 0x00, NULL, HFILL}},
        { &hf_scsi_senddiag_pf,
          {"PF", "scsi.spc.senddiag.pf", FT_BOOLEAN, 8,
           TFS (&scsi_senddiag_pf_val), 0x10, NULL, HFILL}},
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
          TFS (&scsi_log_ppc_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_log_pcr,
          {"PCR", "scsi.log.pcr", FT_BOOLEAN, 8,
          TFS (&scsi_log_pcr_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_log_sp,
          {"SP", "scsi.log.sp", FT_BOOLEAN, 8,
          TFS (&scsi_log_sp_tfs), 0x01, NULL, HFILL}},
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
        &ett_persresv_control
    };
    module_t *scsi_module;

    /* Register the protocol name and description */
    proto_scsi = proto_register_protocol("SCSI", "SCSI", "scsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* add preferences to decode SCSI message */
    scsi_module = prefs_register_protocol (proto_scsi, NULL);
    prefs_register_enum_preference (scsi_module, "decode_scsi_messages_as",
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
}

void
proto_reg_handoff_scsi(void)
{
    scsi_tap = register_tap("scsi");
    data_handle = find_dissector ("data");
}
