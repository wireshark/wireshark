/* TODO make the contracts require that all functions be called with valid
 * pointers for itl and itlq and remove all tests for itl/itlq being NULL
 */
/* TODO audit value parameter for proto_tree_add_boolean() calls */
/* TODO scsi_verdesc_val needs to be updated from appendix D in spc-3 */
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
 * The SCSI decoder has been built right now that it is invoked directly by the
 * SCSI transport layers as compared to the standard mechanism of being invoked
 * via a dissector chain. There are multiple reasons for this:
 * - The SCSI CDB is typically embedded inside the transport along with other
 *   header fields that have nothing to do with SCSI. So, it is required to be

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
#include <string.h>
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
#include "packet-scsi-ssc.h"
#include "packet-scsi-smc.h"

static int proto_scsi                    = -1;
       int hf_scsi_control               = -1;
       int hf_scsi_alloclen16            = -1;
static int hf_scsi_time                  = -1;
static int hf_scsi_request_frame         = -1;
static int hf_scsi_response_frame        = -1;
static int hf_scsi_lun                   = -1;
static int hf_scsi_status                = -1;
static int hf_scsi_spcopcode             = -1;
static int hf_scsi_sbcopcode             = -1;
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
static int hf_scsi_inq_add_len           = -1;
static int hf_scsi_inq_qualifier         = -1;
static int hf_scsi_inq_vendor_id         = -1;
static int hf_scsi_inq_product_id        = -1;
static int hf_scsi_inq_product_rev       = -1;
static int hf_scsi_inq_version_desc      = -1;
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
static int hf_scsi_inq_reladrflags       = -1;
static int hf_scsi_inq_sync              = -1;
static int hf_scsi_inq_reladr            = -1;
static int hf_scsi_inq_linked            = -1;
static int hf_scsi_inq_cmdque            = -1;
static int hf_scsi_inq_bqueflags         = -1;
static int hf_scsi_inq_bque              = -1;
static int hf_scsi_inq_encserv           = -1;
static int hf_scsi_inq_multip            = -1;
static int hf_scsi_inq_mchngr            = -1;
static int hf_scsi_inq_sccsflags         = -1;
static int hf_scsi_inq_sccs              = -1;
static int hf_scsi_inq_acc               = -1;
static int hf_scsi_inq_tpc               = -1;
static int hf_scsi_inq_protect           = -1;
static int hf_scsi_inq_tpgs              = -1;
static int hf_scsi_inq_acaflags          = -1;
static int hf_scsi_inq_normaca           = -1;
static int hf_scsi_inq_hisup             = -1;
static int hf_scsi_inq_aerc              = -1;
static int hf_scsi_inq_trmtsk            = -1;
static int hf_scsi_inq_rdf               = -1;
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
static int hf_scsi_fragments = -1;
static int hf_scsi_fragment = -1;
static int hf_scsi_fragment_overlap = -1;
static int hf_scsi_fragment_overlap_conflict = -1;
static int hf_scsi_fragment_multiple_tails = -1;
static int hf_scsi_fragment_too_long_fragment = -1;
static int hf_scsi_fragment_error = -1;
static int hf_scsi_reassembled_in = -1;

static gint ett_scsi         = -1;
static gint ett_scsi_page    = -1;
static gint ett_scsi_inq_acaflags = -1;
static gint ett_scsi_inq_sccsflags = -1;
static gint ett_scsi_inq_bqueflags = -1;
static gint ett_scsi_inq_reladrflags = -1;
static gint ett_scsi_fragments = -1;
static gint ett_scsi_fragment  = -1;

static int scsi_tap = -1;

/* Defragment of SCSI DATA IN/OUT */
static gboolean scsi_defragment = FALSE;

static GHashTable *scsi_fragment_table = NULL;
static GHashTable *scsi_reassembled_table = NULL;

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
	&hf_scsi_reassembled_in,
	"fragments"
};



typedef guint32 scsi_cmnd_type;
typedef guint32 scsi_device_type;

/* Valid SCSI Command Types */
#define SCSI_CMND_SPC2                   1
#define SCSI_CMND_SBC2                   2
#define SCSI_CMND_SSC2                   3
#define SCSI_CMND_SMC2                   4
#define SCSI_CMND_MMC                    5

/* SPC and SPC-2 Commands */
static const value_string scsi_spc2_vals[] = {
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


const value_string scsi_sbc2_vals[] = {
    {SCSI_SPC2_EXTCOPY           , "Extended Copy"},
    {SCSI_SPC2_INQUIRY           , "Inquiry"},
    {SCSI_SBC2_FORMATUNIT        , "Format Unit"},
    {SCSI_SBC2_LOCKUNLKCACHE10   , "Lock Unlock Cache(10)"},
    {SCSI_SBC2_LOCKUNLKCACHE16   , "Lock Unlock Cache(16)"},
    {SCSI_SPC2_LOGSELECT         , "Log Select"},
    {SCSI_SPC2_LOGSENSE          , "Log Sense"},
    {SCSI_SPC2_MODESELECT6       , "Mode Select(6)"},
    {SCSI_SPC2_MODESELECT10      , "Mode Select(10)"},
    {SCSI_SPC2_MODESENSE6        , "Mode Sense(6)"},
    {SCSI_SPC2_MODESENSE10       , "Mode Sense(10)"},
    {SCSI_SPC2_PERSRESVIN        , "Persistent Reserve In"},
    {SCSI_SPC2_PERSRESVOUT       , "Persistent Reserve Out"},
    {SCSI_SBC2_PREFETCH10        , "Pre-Fetch(10)"},
    {SCSI_SBC2_PREFETCH16        , "Pre-Fetch(16)"},
    {SCSI_SPC2_PREVMEDREMOVAL    , "Prevent/Allow Medium Removal"},
    {SCSI_SBC2_READ6             , "Read(6)"},
    {SCSI_SBC2_READ10            , "Read(10)"},
    {SCSI_SBC2_READ12            , "Read(12)"},
    {SCSI_SBC2_READ16            , "Read(16)"},
    {SCSI_SBC2_READCAPACITY10    , "Read Capacity(10)"},
    {SCSI_SPC2_REPORTLUNS        , "Report LUNs"},
    {SCSI_SPC2_REQSENSE          , "Request Sense"},
    {SCSI_SBC2_SERVICEACTIONIN16 , "Service Action In(16)"},
    {SCSI_SBC2_READDEFDATA10     , "Read Defect Data(10)"},
    {SCSI_SBC2_READDEFDATA12     , "Read Defect Data(12)"},
    {SCSI_SBC2_READLONG          , "Read Long"},
    {SCSI_SBC2_REASSIGNBLKS      , "Reassign Blocks"},
    {SCSI_SBC2_REBUILD16         , "Rebuild(16)"},
    {SCSI_SBC2_REBUILD32         , "Rebuild(32)"},
    {SCSI_SBC2_REGENERATE16      , "Regenerate(16)"},
    {SCSI_SBC2_REGENERATE32      , "Regenerate(32)"},
    {SCSI_SBC2_SEEK10            , "Seek(10)"},
    {SCSI_SPC2_SENDDIAG          , "Send Diagnostic"},
    {SCSI_SBC2_SETLIMITS10       , "Set Limits(10)"},
    {SCSI_SBC2_SETLIMITS12       , "Set Limits(12)"},
    {SCSI_SBC2_STARTSTOPUNIT     , "Start Stop Unit"},
    {SCSI_SBC2_SYNCCACHE10       , "Synchronize Cache(10)"},
    {SCSI_SBC2_SYNCCACHE16       , "Synchronize Cache(16)"},
    {SCSI_SPC2_TESTUNITRDY       , "Test Unit Ready"},
    {SCSI_SBC2_VERIFY10          , "Verify(10)"},
    {SCSI_SBC2_VERIFY12          , "Verify(12)"},
    {SCSI_SBC2_VERIFY16          , "Verify(16)"},
    {SCSI_SBC2_WRITE6            , "Write(6)"},
    {SCSI_SBC2_WRITE10           , "Write(10)"},
    {SCSI_SBC2_WRITE12           , "Write(12)"},
    {SCSI_SBC2_WRITE16           , "Write(16)"},
    {SCSI_SPC2_WRITEBUFFER       , "Write Buffer"},
    {SCSI_SBC2_WRITENVERIFY10    , "Write & Verify(10)"},
    {SCSI_SBC2_WRITENVERIFY12    , "Write & Verify(12)"},
    {SCSI_SBC2_WRITENVERIFY16    , "Write & Verify(16)"},
    {SCSI_SBC2_WRITELONG         , "Write Long"},
    {SCSI_SBC2_WRITESAME10       , "Write Same(10)"},
    {SCSI_SBC2_WRITESAME16       , "Write Same(16)"},
    {SCSI_SBC2_XDREAD10          , "XdRead(10)"},
    {SCSI_SBC2_XDREAD32          , "XdRead(32)"},
    {SCSI_SBC2_XDWRITE10         , "XdWrite(10)"},
    {SCSI_SBC2_XDWRITE32         , "XdWrite(32)"},
    {SCSI_SBC2_XDWRITEREAD10     , "XdWriteRead(10)"},
    {SCSI_SBC2_XDWRITEREAD32     , "XdWriteRead(32)"},
    {SCSI_SBC2_XDWRITEEXTD16     , "XdWrite Extended(16)"},
    {SCSI_SBC2_XDWRITEEXTD32     , "XdWrite Extended(32)"},
    {SCSI_SBC2_XPWRITE10         , "XpWrite(10)"},
    {SCSI_SBC2_XPWRITE32         , "XpWrite(32)"},
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
    {0x2, "Error Counter (write) Page"},
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
    {"objectbased", "Object Based Storage Device", SCSI_DEV_OSD},
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
    {0x0020, "SAM (no version claimed)"},
    {0x003c, "SAM ANSI X3.270:1996"},
    {0x003b, "SAM T10/0994 revision 18"},
    {0x0040, "SAM-2 (no version claimed)"},
    {0x0120, "SPC (no version claimed)"},
    {0x013c, "SPC ANSI X3.301:1997"},
    {0x013b, "SPC T10/0995 revision 11a"},
    {0x0180, "SBC (no version claimed)"},
    {0x019c, "SBC ANSI NCITS.306:1998"},
    {0x019b, "SBC T10/0996 revision 08c"},
    {0x01c0, "SES (no version claimed)"},
    {0x01dc, "SES ANSI NCITS.305:1998"},
    {0x01db, "SES T10/1212 revision 08b"},
    {0x01de, "SES ANSI NCITS.305:1998 w/ Amendment ANSI NCITS.305/AM1:2000"},
    {0x01dd, "SES T10/1212 revision 08b w/ Amendment ANSI NCITS.305/AM1:2000"},
    {0x0260, "SPC-2 (no version claimed)"},
    {0x0267, "SPC-2 T10/1236 revision 12"},
    {0x0269, "SPC-2 T10/1236 revision 18"},
    {0x0300, "SPC-3 (no version claimed)"},
    {0x0320, "SBC-2 (no version claimed)"},
    {0x08c0, "FCP (no version claimed)"},
    {0x08dc, "FCP ANSI X3.269:1996"},
    {0x08db, "FCP T10/0993 revision 12"},
    {0x0900, "FCP-2 (no version claimed)"},
    {0x0901, "FCP-2 T10/1144 revision 4"},
    {0x0960, "iSCSI (no version claimed)"},
    {0x0d20, "FC-PH (no version claimed)"},
    {0x0d40, "FC-AL (No Version)"},
    {0x0d5c, "FC-AL ANSI X3.272:1996"},
    {0x0d60, "FC-AL-2 (no version claimed)"},
    {0x0d61, "FC-AL-2 T11/1133 revision 7.0"},
    {0x0d7c, "FC-AL-2 ANSI NCITS.332:1999"},
    {0x0d80, "FC-PH-3 (no version claimed)"},
    {0x0d9c, "FC-PH-3 ANSI X3.303-1998"},
    {0x0da0, "FC-FS (no version claimed)"},
    {0x0db7, "FC-FS T11/1331 revision 1.2"},
    {0x1320, "FC-FLA (no version claimed)"},
    {0x133c, "FC-FLA ANSI NCITS TR-20:1998"},
    {0x133b, "FC-FLA T11/1235 revision 7"},
    {0x1340, "FC-PLDA (no version claimed)"},
    {0x135c, "FC-PLDA ANSI NCITS TR-19:1998"},
    {0x135b, "FC-PLDA T11/1162 revision 2.1"},
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

const value_string scsi_asc_val[] = {
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


#define SCSI_INQ_ACAFLAGS_AERC		0x80
#define SCSI_INQ_ACAFLAGS_TRMTSK	0x40
#define SCSI_INQ_ACAFLAGS_NORMACA	0x20
#define SCSI_INQ_ACAFLAGS_HISUP		0x10

static const value_string inq_rdf_vals[] = {
	{ 2, "SPC-2/SPC-3" },
	{ 0, NULL }
};

/* This dissects byte 3 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc3_inq_acaflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
	guint8 flags;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_scsi_inq_acaflags, tvb, offset, 1, 0);
		tree = proto_item_add_subtree (item, ett_scsi_inq_acaflags);
	}

        flags=tvb_get_guint8 (tvb, offset);

	/* AERC (obsolete in spc3 and forward) */
	proto_tree_add_boolean(tree, hf_scsi_inq_aerc, tvb, offset, 1, flags);
	if(flags&SCSI_INQ_ACAFLAGS_AERC){
		proto_item_append_text(item, "  AERC");
	}
	flags&=(~SCSI_INQ_ACAFLAGS_AERC);

	/* TRMTSK (obsolete in spc2 and forward) */
	proto_tree_add_boolean(tree, hf_scsi_inq_trmtsk, tvb, offset, 1, flags);
	if(flags&SCSI_INQ_ACAFLAGS_TRMTSK){
		proto_item_append_text(item, "  TrmTsk");
	}
	flags&=(~SCSI_INQ_ACAFLAGS_TRMTSK);

	/* NormACA */
	proto_tree_add_boolean(tree, hf_scsi_inq_normaca, tvb, offset, 1, flags);
	if(flags&SCSI_INQ_ACAFLAGS_NORMACA){
		proto_item_append_text(item, "  NormACA");
	}
	flags&=(~SCSI_INQ_ACAFLAGS_NORMACA);

	/* HiSup */
	proto_tree_add_boolean(tree, hf_scsi_inq_hisup, tvb, offset, 1, flags);
	if(flags&SCSI_INQ_ACAFLAGS_HISUP){
		proto_item_append_text(item, "  HiSup");
	}
	flags&=(~SCSI_INQ_ACAFLAGS_HISUP);

	/* Response Data Format */
	proto_tree_add_item (tree, hf_scsi_inq_rdf, tvb, offset, 1, 0);
	proto_item_append_text(item, "  RDF:%s", val_to_str(flags&0x0f, inq_rdf_vals, "Unknown:%d"));

	offset+=1;
	return offset;
}

#define SCSI_INQ_SCCSFLAGS_SCCS		0x80
#define SCSI_INQ_SCCSFLAGS_ACC		0x40
#define SCSI_INQ_SCCSFLAGS_TPC		0x08
#define SCSI_INQ_SCCSFLAGS_PROTECT	0x01

static const value_string inq_tpgs_vals[] = {
	{ 0, "Assymetric LU Access not supported" },
	{ 1, "Implicit Assymetric LU Access supported" },
	{ 2, "Explicit LU Access supported" },
	{ 3, "Both Implicit and Explicit LU Access supported" },
	{ 0, NULL }
};

/* This dissects byte 5 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc3_inq_sccsflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
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


#define SCSI_INQ_BQUEFLAGS_BQUE		0x80
#define SCSI_INQ_BQUEFLAGS_ENCSERV	0x40
#define SCSI_INQ_BQUEFLAGS_MULTIP	0x10
#define SCSI_INQ_BQUEFLAGS_MCHNGR	0x08

/* This dissects byte 6 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc3_inq_bqueflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
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

#define SCSI_INQ_RELADRFLAGS_RELADR		0x80
#define SCSI_INQ_RELADRFLAGS_SYNC		0x10
#define SCSI_INQ_RELADRFLAGS_LINKED		0x08
#define SCSI_INQ_RELADRFLAGS_CMDQUE		0x02

/* This dissects byte 7 of the SPC-3 standard INQ data (SPC-3 6.4.2) */
static int
dissect_spc3_inq_reladrflags(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
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
dissect_spc3_inquiry (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint32 payload_len, scsi_task_data_t *cdata)
{
    guint8 flags, i;

    if (!isreq && (cdata == NULL || !(cdata->itlq->flags & 0x3))
    && (tvb_length_remaining(tvb, offset)>=1) ) {
        /*
         * INQUIRY response with device type information; add device type
         * to list of known devices & their types if not already known.
         */
        if(cdata && cdata->itl){
            cdata->itl->cmdset=tvb_get_guint8(tvb, offset)&SCSI_DEV_BITS;
        }
    }

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        if (cdata) {
            cdata->itlq->flags = flags;
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
	/* we need the alloc_len in the response */
	if(cdata){
		cdata->itlq->alloc_len=tvb_get_guint8(tvb, offset+3);
	}

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    } else if (!isreq) {
	if (!cdata) {
		return;
	}

        if (cdata->itlq->flags & 0x1) {
       	    dissect_scsi_evpd (tvb, pinfo, tree, offset, payload_len);
       	    return;
       	}
	if (cdata->itlq->flags & 0x2) {
       	    dissect_scsi_cmddt (tvb, pinfo, tree, offset, payload_len);
       	    return;
       	}


	/* These pdus are sometimes truncated by SCSI allocation length
	 * in the CDB
	 */
	TRY_SCSI_CDB_ALLOC_LEN(pinfo, tvb, offset, cdata->itlq->alloc_len);

	/* Qualifier and DeviceType */
        proto_tree_add_item (tree, hf_scsi_inq_qualifier, tvb, offset,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_inq_devtype, tvb, offset, 1, 0);
	offset+=1;

	/* RMB */
	proto_tree_add_item(tree, hf_scsi_inq_rmb,  tvb, offset, 1, 0);
	offset+=1;

	/* Version */
        proto_tree_add_item (tree, hf_scsi_inq_version, tvb, offset, 1, 0);
	offset+=1;

	/* aca flags */
	offset=dissect_spc3_inq_acaflags(tvb, offset, tree);

	/* Additional Length */
	SET_SCSI_DATA_END(tvb_get_guint8(tvb, offset)+offset);
        proto_tree_add_item(tree, hf_scsi_inq_add_len, tvb, offset, 1, 0);
	offset+=1;

	/* sccs flags */
	offset=dissect_spc3_inq_sccsflags(tvb, offset, tree);

	/* bque flags */
	offset=dissect_spc3_inq_bqueflags(tvb, offset, tree);

	/* reladdr flags */
	offset=dissect_spc3_inq_reladrflags(tvb, offset, tree);

	/* vendor id */
	proto_tree_add_item(tree, hf_scsi_inq_vendor_id, tvb, offset, 8, 0);
	offset+=8;

	/* product id */
	proto_tree_add_item(tree, hf_scsi_inq_product_id, tvb, offset, 16, 0);
	offset+=16;

	/* product revision level */
	proto_tree_add_item(tree, hf_scsi_inq_product_rev, tvb, offset, 4, 0);
	offset+=4;

	/* vendor specific, 20 bytes */
	offset+=20;

	/* clocking, qas, ius */
	offset++;

	/* reserved */
	offset++;

	/* version descriptors */
	for(i=0;i<8;i++){
		proto_tree_add_item(tree, hf_scsi_inq_version_desc, tvb, offset, 2, 0);
		offset+=2;
	}

	END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

void
dissect_spc3_extcopy (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
		      proto_tree *tree _U_, guint offset _U_,
		      gboolean isreq _U_, gboolean iscdb _U_,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

}

void
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
                                    flags, "PCR = %u, SP = %u", (flags & 0x2) >> 1,
                                    flags & 0x1);
        proto_tree_add_uint_format (tree, hf_scsi_logsel_pc, tvb, offset+1, 1,
                                    tvb_get_guint8 (tvb, offset+1),
                                    "PC: 0x%x", (flags & 0xC0) >> 6);
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

void
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

void
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
        offset += 2;	/* skip LongLBA byte and reserved byte */
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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
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
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset, cdata->itl->cmdset&SCSI_CMDSET_MASK);
            offset += plen;
            tot_len -= plen;
        }
    }
}

void
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

void
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
        cdata->itlq->flags = tvb_get_guint8 (tvb, offset+1);
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

void
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

void
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

void
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

void
dissect_spc3_reportluns (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;
    gint listlen;

    if (isreq && iscdb) {
	proto_tree_add_item (tree, hf_scsi_select_report, tvb, offset+1, 1, 0);

        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb, offset+5, 4, 0);
	if(cdata){
		cdata->itlq->alloc_len=tvb_get_ntohl(tvb, offset+5);
	}

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    } else if (!isreq) {
	if (!cdata) {
		return;
	}

	TRY_SCSI_CDB_ALLOC_LEN(pinfo, tvb, offset, cdata->itlq->alloc_len);
        listlen = tvb_get_ntohl(tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 4, "LUN List Length: %u",
                             listlen);
        offset += 8;

	while(listlen>0){
            if (!tvb_get_guint8 (tvb, offset))
                proto_tree_add_item (tree, hf_scsi_rluns_lun, tvb, offset+1, 1,
                                     0);
            else
                proto_tree_add_item (tree, hf_scsi_rluns_multilun, tvb, offset,
                                     8, 0);
            offset+=8;
            listlen-=8;
        }
	END_TRY_SCSI_CDB_ALLOC_LEN;
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

void
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

void
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

void
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

void
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

void
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

void
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

void
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

void
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

const value_string service_action_vals[] = {
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

void
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

void
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

    csdata=get_cmdset_data(itlq, itl);   /* will gassert if itlq is null */

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
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
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
/*SPC 0x00*/{dissect_spc3_testunitready},
/*SBC 0x01*/{NULL},
/*SBC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc3_requestsense},
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
/*SPC 0x12*/{dissect_spc3_inquiry},
/*SBC 0x13*/{NULL},
/*SBC 0x14*/{NULL},
/*SPC 0x15*/{dissect_spc3_modeselect6},
/*SBC 0x16*/{NULL},
/*SBC 0x17*/{NULL},
/*SBC 0x18*/{NULL},
/*SBC 0x19*/{NULL},
/*SPC 0x1a*/{dissect_spc3_modesense6},
/*SBC 0x1b*/{dissect_sbc2_startstopunit},
/*SBC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc3_senddiagnostic},
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
/*SPC 0x3b*/{dissect_spc3_writebuffer},
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
/*SPC 0x4c*/{dissect_spc3_logselect},
/*SPC 0x4d*/{dissect_spc3_logsense},
/*SBC 0x4e*/{NULL},
/*SBC 0x4f*/{NULL},
/*SBC 0x50*/{NULL},
/*SBC 0x51*/{NULL},
/*SBC 0x52*/{NULL},
/*SBC 0x53*/{NULL},
/*SBC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc3_modeselect10},
/*SBC 0x56*/{NULL},
/*SBC 0x57*/{NULL},
/*SBC 0x58*/{NULL},
/*SBC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc3_modesense10},
/*SBC 0x5b*/{NULL},
/*SBC 0x5c*/{NULL},
/*SBC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc3_persistentreservein},
/*SPC 0x5f*/{dissect_spc3_persistentreserveout},
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
/*SPC 0x83*/{dissect_spc3_extcopy},
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
/*SPC 0xa0*/{dissect_spc3_reportluns},
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



/* This function must be called with walid pointers for both itlq and itl */
void
dissect_scsi_cdb (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  gint devtype_arg, itlq_nexus_t *itlq, itl_nexus_t *itl)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode;
    scsi_device_type devtype;
    const gchar *valstr;
    scsi_task_data_t *cdata;
    const char *old_proto;
    cmdset_t *csdata;


    old_proto=pinfo->current_proto;
    pinfo->current_proto="SCSI";

    if(!itlq){
        g_assert_not_reached();
    }
    if(!itl){
        g_assert_not_reached();
    }

    opcode = tvb_get_guint8 (tvb, offset);
    itlq->scsi_opcode=opcode;
    csdata=get_cmdset_data(itlq, itl);

    if (devtype_arg != SCSI_DEV_UNKNOWN) {
        devtype = devtype_arg;
    } else {
        if (itl) {
            devtype = itl->cmdset;
        } else {
            devtype = (scsi_device_type)scsi_def_devtype;
        }
    }

    if ((valstr = match_strval (opcode, scsi_spc2_vals)) == NULL) {
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
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
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
    guint8 opcode = 0xFF;
    scsi_device_type devtype=0xff;
    scsi_task_data_t *cdata = NULL;
    int payload_len;
    const char *old_proto;
    cmdset_t *csdata;
    guint32 expected_length;
    fragment_data *ipfd_head=NULL;
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

    opcode = cdata->itlq->scsi_opcode;
    devtype = cdata->itl->cmdset&SCSI_CMDSET_MASK;

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
        ti=proto_tree_add_uint_format(scsi_tree, hf_scsi_inq_devtype, tvb, 0, 0, itl->cmdset&SCSI_CMDSET_MASK, "Command Set:%s (0x%02x) %s", val_to_str(itl->cmdset&SCSI_CMDSET_MASK, scsi_devtype_val, "Unknown"), itl->cmdset&SCSI_CMDSET_MASK,itl->cmdset&SCSI_CMDSET_DEFAULT?"(Using default commandset)":"");
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
    if( (!relative_offset) && (tvb_length_remaining(tvb, offset)==expected_length) ){
        goto dissect_the_payload;
    }


    /* Start reassembly */

    if (tvb_length_remaining(tvb, offset) >= 0 &&
	    (tvb_length_remaining(tvb,offset) + relative_offset) != expected_length) {
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
        if (opcode == SCSI_SPC2_INQUIRY) {
            dissect_spc3_inquiry (next_tvb, pinfo, scsi_tree, offset, isreq,
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
        g_assert_not_reached();
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
        csdata->hf_opcode=hf_scsi_sbcopcode;
        csdata->cdb_vals=scsi_sbc2_vals;
        csdata->cdb_table=sbc;
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
        csdata->cdb_vals=scsi_spc2_vals;
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
           NULL, 0x0, "LUN", HFILL}},
	{ &hf_scsi_status,
	  { "Status", "scsi.status", FT_UINT8, BASE_HEX,
	   VALS(scsi_status_val), 0, "SCSI command status value", HFILL }},
        { &hf_scsi_spcopcode,
          {"SPC-2 Opcode", "scsi.spc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc2_vals), 0x0, "", HFILL}},
        { &hf_scsi_sbcopcode,
          {"SBC-2 Opcode", "scsi.sbc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc2_vals), 0x0, "", HFILL}},
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
           VALS (scsi_logsns_page_val), 0x3F, "", HFILL}},
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
        { &hf_scsi_inq_add_len,
          {"Additional Length", "scsi.inquiry.add_len", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_scsi_inq_qualifier,
          {"Peripheral Qualifier", "scsi.inquiry.qualifier", FT_UINT8, BASE_HEX,
           VALS (scsi_qualifier_val), 0xE0, "", HFILL}},
        { &hf_scsi_inq_vendor_id,
          {"Vendor Id", "scsi.inquiry.vendor_id", FT_STRING, BASE_NONE,
           NULL, 0, "", HFILL}},
        { &hf_scsi_inq_product_id,
          {"Product Id", "scsi.inquiry.product_id", FT_STRING, BASE_NONE,
           NULL, 0, "", HFILL}},
        { &hf_scsi_inq_product_rev,
          {"Product Revision Level", "scsi.inquiry.product_rev", FT_STRING, BASE_NONE,
           NULL, 0, "", HFILL}},
        { &hf_scsi_inq_version_desc,
          {"Version Description", "scsi.inquiry.version_desc", FT_UINT16, BASE_HEX,
           VALS(scsi_verdesc_val), 0, "", HFILL}},
        { &hf_scsi_inq_devtype,
          {"Peripheral Device Type", "scsi.inquiry.devtype", FT_UINT8, BASE_HEX,
           VALS (scsi_devtype_val), SCSI_DEV_BITS, "", HFILL}},
        { &hf_scsi_inq_rmb,
          {"Removable", "scsi.inquiry.removable", FT_BOOLEAN, 8,
           TFS (&scsi_removable_val), 0x80, "", HFILL}},
        { & hf_scsi_inq_version,
          {"Version", "scsi.inquiry.version", FT_UINT8, BASE_HEX,
           VALS (scsi_inquiry_vers_val), 0x0, "", HFILL}},
        { &hf_scsi_inq_reladrflags,
          {"Flags", "scsi.inquiry.reladrflags", FT_UINT8, BASE_HEX, NULL, 0,
           "", HFILL}},
        { &hf_scsi_inq_reladr,
          {"RelAdr", "scsi.inquiry.reladr", FT_BOOLEAN, 8, TFS(&reladr_tfs), SCSI_INQ_RELADRFLAGS_RELADR,
           "", HFILL}},
        { &hf_scsi_inq_sync,
          {"Sync", "scsi.inquiry.sync", FT_BOOLEAN, 8, TFS(&sync_tfs), SCSI_INQ_RELADRFLAGS_SYNC,
           "", HFILL}},
        { &hf_scsi_inq_linked,
          {"Linked", "scsi.inquiry.linked", FT_BOOLEAN, 8, TFS(&linked_tfs), SCSI_INQ_RELADRFLAGS_LINKED,
           "", HFILL}},
        { &hf_scsi_inq_cmdque,
          {"CmdQue", "scsi.inquiry.cmdque", FT_BOOLEAN, 8, TFS(&cmdque_tfs), SCSI_INQ_RELADRFLAGS_CMDQUE,
           "", HFILL}},
        { &hf_scsi_inq_bqueflags,
          {"Flags", "scsi.inquiry.bqueflags", FT_UINT8, BASE_HEX, NULL, 0,
           "", HFILL}},
        { &hf_scsi_inq_bque,
          {"BQue", "scsi.inquiry.bque", FT_BOOLEAN, 8, TFS(&bque_tfs), SCSI_INQ_BQUEFLAGS_BQUE,
           "", HFILL}},
        { &hf_scsi_inq_encserv,
          {"EncServ", "scsi.inquiry.encserv", FT_BOOLEAN, 8, TFS(&encserv_tfs), SCSI_INQ_BQUEFLAGS_ENCSERV,
           "", HFILL}},
        { &hf_scsi_inq_multip,
          {"MultiP", "scsi.inquiry.multip", FT_BOOLEAN, 8, TFS(&multip_tfs), SCSI_INQ_BQUEFLAGS_MULTIP,
           "", HFILL}},
        { &hf_scsi_inq_mchngr,
          {"MChngr", "scsi.inquiry.mchngr", FT_BOOLEAN, 8, TFS(&mchngr_tfs), SCSI_INQ_BQUEFLAGS_MCHNGR,
           "", HFILL}},
        { &hf_scsi_inq_sccsflags,
          {"Flags", "scsi.inquiry.sccsflags", FT_UINT8, BASE_HEX, NULL, 0,
           "", HFILL}},
        { &hf_scsi_inq_sccs,
          {"SCCS", "scsi.inquiry.sccs", FT_BOOLEAN, 8, TFS(&sccs_tfs), SCSI_INQ_SCCSFLAGS_SCCS,
           "", HFILL}},
        { &hf_scsi_inq_acc,
          {"ACC", "scsi.inquiry.acc", FT_BOOLEAN, 8, TFS(&acc_tfs), SCSI_INQ_SCCSFLAGS_ACC,
           "", HFILL}},
        { &hf_scsi_inq_tpc,
          {"3PC", "scsi.inquiry.tpc", FT_BOOLEAN, 8, TFS(&tpc_tfs), SCSI_INQ_SCCSFLAGS_TPC,
           "", HFILL}},
        { &hf_scsi_inq_protect,
          {"Protect", "scsi.inquiry.protect", FT_BOOLEAN, 8, TFS(&protect_tfs), SCSI_INQ_SCCSFLAGS_PROTECT,
           "", HFILL}},
        { &hf_scsi_inq_tpgs,
          {"TPGS", "scsi.inquiry.tpgs", FT_UINT8, BASE_DEC, VALS(inq_tpgs_vals), 0x30,
           "", HFILL}},
        { &hf_scsi_inq_acaflags,
          {"Flags", "scsi.inquiry.acaflags", FT_UINT8, BASE_HEX, NULL, 0,
           "", HFILL}},
        { &hf_scsi_inq_normaca,
          {"NormACA", "scsi.inquiry.normaca", FT_BOOLEAN, 8, TFS(&normaca_tfs), SCSI_INQ_ACAFLAGS_NORMACA,
           "", HFILL}},
        { &hf_scsi_inq_hisup,
          {"HiSup", "scsi.inquiry.hisup", FT_BOOLEAN, 8, TFS(&hisup_tfs), SCSI_INQ_ACAFLAGS_HISUP,
           "", HFILL}},
        { &hf_scsi_inq_aerc,
          {"AERC", "scsi.inquiry.aerc", FT_BOOLEAN, 8, TFS(&aerc_tfs), SCSI_INQ_ACAFLAGS_AERC,
           "AERC is obsolete from SPC-3 and forward", HFILL}},
        { &hf_scsi_inq_trmtsk,
          {"TrmTsk", "scsi.inquiry.trmtsk", FT_BOOLEAN, 8, TFS(&trmtsk_tfs), SCSI_INQ_ACAFLAGS_TRMTSK,
           "TRMTSK is obsolete from SPC-2 and forward", HFILL}},
        { &hf_scsi_inq_rdf,
          {"Response Data Format", "scsi.inquiry.rdf", FT_UINT8, BASE_DEC, VALS(inq_rdf_vals), 0x0f,
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
	    "SCSI Fragments", HFILL }},

	{ &hf_scsi_fragment_overlap,
	  { "Fragment overlap",	"scsi.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment overlaps with other fragments", HFILL }},

	{ &hf_scsi_fragment_overlap_conflict,
	  { "Conflicting data in fragment overlap",	"scsi.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Overlapping fragments contained conflicting data", HFILL }},

	{ &hf_scsi_fragment_multiple_tails,
	  { "Multiple tail fragments found",	"scsi.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Several tails were found when defragmenting the packet", HFILL }},

	{ &hf_scsi_fragment_too_long_fragment,
	  { "Fragment too long",	"scsi.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment contained data past end of packet", HFILL }},

	{ &hf_scsi_fragment_error,
	  { "Defragmentation error", "scsi.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "Defragmentation error due to illegal fragments", HFILL }},

	{ &hf_scsi_fragment,
	  { "SCSI DATA Fragment", "scsi.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "SCSI DATA Fragment", HFILL }},

	{ &hf_scsi_reassembled_in,
	  { "Reassembled SCSI DATA in frame", "scsi.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "This SCSI DATA packet is reassembled in this frame", HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_scsi,
	&ett_scsi_page,
	&ett_scsi_inq_acaflags,
	&ett_scsi_inq_sccsflags,
	&ett_scsi_inq_bqueflags,
	&ett_scsi_inq_reladrflags,
	&ett_scsi_fragments,
	&ett_scsi_fragment,
    };
    module_t *scsi_module;

    /* Register the protocol name and description */
    proto_scsi = proto_register_protocol("SCSI", "SCSI", "scsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    data_handle = find_dissector ("data");

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
}
