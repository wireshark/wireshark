/* packet-scsi.c
 * Routines for decoding SCSI CDBs and responses
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-scsi.c,v 1.6 2002/03/12 11:30:45 guy Exp $
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
 *   void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *, guint,
 *   guint); 
 * o dissect_scsi_payload - invoked to decode SCSI responses
 *   void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *, guint,
 *                              gboolean, guint32);
 *   The final parameter is the length of the response field that is negotiated
 *   as part of the SCSI transport layer. If this is not tracked by the
 *   transport, it can be set to 0.
 * o dissect_scsi_rsp - invoked to destroy the data structures associated with a
 *                      SCSI task.
 *   void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *);
 * o dissect_scsi_snsinfo - invoked to decode the sense data provided in case of
 *                          an error.
 *   void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint,
 *   guint);
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include <string.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include "prefs.h"
#include "packet-scsi.h"

static int proto_scsi                    = -1;
static int hf_scsi_spcopcode             = -1;
static int hf_scsi_sbcopcode             = -1;
static int hf_scsi_control               = -1;
static int hf_scsi_inquiry_flags         = -1;
static int hf_scsi_inquiry_evpd_page     = -1;
static int hf_scsi_inquiry_cmdt_page     = -1;
static int hf_scsi_alloclen              = -1;
static int hf_scsi_logsel_flags          = -1;
static int hf_scsi_log_pc                = -1;
static int hf_scsi_paramlen              = -1;
static int hf_scsi_logsns_flags          = -1;
static int hf_scsi_logsns_pagecode       = -1;
static int hf_scsi_paramlen16            = -1;
static int hf_scsi_modesel_flags         = -1;
static int hf_scsi_alloclen16            = -1;
static int hf_scsi_modesns_pc            = -1;
static int hf_scsi_modesns_pagecode      = -1;
static int hf_scsi_modesns_flags         = -1;
static int hf_scsi_persresvin_svcaction  = -1;
static int hf_scsi_persresvout_svcaction = -1;
static int hf_scsi_persresv_scope        = -1;
static int hf_scsi_persresv_type         = -1;
static int hf_scsi_release_flags         = -1;
static int hf_scsi_release_thirdpartyid  = -1;
static int hf_scsi_alloclen32            = -1;
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
static int hf_scsi_inq_devtype           = -1;
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
static int hf_scsi_sscopcode             = -1;
static int hf_scsi_add_cdblen = -1;
static int hf_scsi_svcaction = -1;


static gint ett_scsi         = -1;
static gint ett_scsi_page    = -1;

typedef guint32 scsi_cmnd_type;
typedef guint32 scsi_device_type;

/* Valid SCSI Device Types */
#define SCSI_CMND_SPC2                   1
#define SCSI_CMND_SBC2                   2
#define SCSI_CMND_SSC2                   3

/* SPC-2 Commands */

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
    {SCSI_SPC2_EXTCOPY           , "Extended Copy"},
    {SCSI_SPC2_INQUIRY           , "Inquiry"},
    {SCSI_SPC2_LOGSELECT         , "Log Select"},
    {SCSI_SPC2_LOGSENSE          , "Log Sense"},
    {SCSI_SPC2_MODESELECT6       , "Mode Select (6)"},
    {SCSI_SPC2_MODESELECT10      , "Mode Select (10)"},
    {SCSI_SPC2_MODESENSE6        , "Mode Sense (6)"},
    {SCSI_SPC2_MODESENSE10       , "Mode Sense (10)"},
    {SCSI_SPC2_PERSRESVIN        , "Persistent Reserve In"},
    {SCSI_SPC2_PERSRESVOUT       , "Persistent Reserve Out"},
    {SCSI_SPC2_PREVMEDREMOVAL    , "Prevent Allow Medium Removal"},
    {SCSI_SPC2_RCVCOPYRESULTS    , "Receive Copy Results"},
    {SCSI_SPC2_RCVDIAGRESULTS    , "Receive Diagnostics Results"},
    {SCSI_SPC2_READBUFFER        , "Read Buffer"},
    {SCSI_SPC2_RELEASE6          , "Release (6)"},
    {SCSI_SPC2_RELEASE10         , "Release (10)"},
    {SCSI_SPC2_REPORTDEVICEID    , "Report Device ID"},
    {SCSI_SPC2_REPORTLUNS        , "Report LUNs"},
    {SCSI_SPC2_REQSENSE          , "Request Sense"},
    {SCSI_SPC2_RESERVE6          , "Reserve (6)"},
    {SCSI_SPC2_RESERVE10         , "Reserve (10)"},
    {SCSI_SPC2_TESTUNITRDY       , "Test Unit Ready"},
    {SCSI_SPC2_WRITEBUFFER       , "Write Buffer"},
    {SCSI_SPC2_VARLENCDB         , "Variable Length CDB"},
    {0, NULL},
};

/* SBC-2 Commands */
#define SCSI_SBC2_FORMATUNIT             0x04
#define SCSI_SBC2_LOCKUNLKCACHE10        0x36
#define SCSI_SPC2_LOCKUNLKCACHE16        0x92
#define SCSI_SBC2_PREFETCH10             0x34
#define SCSI_SBC2_PREFETCH16             0x90
#define SCSI_SBC2_READ6                  0x08
#define SCSI_SBC2_READ10                 0x28
#define SCSI_SBC2_READ12                 0xA8
#define SCSI_SBC2_READ16                 0x88
#define SCSI_SBC2_READCAPACITY           0x25
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
    {SCSI_SBC2_LOCKUNLKCACHE10, "Lock Unlock Cache (10)"},
    {SCSI_SPC2_LOCKUNLKCACHE16, "Lock Unlock Cache (16)"},
    {SCSI_SBC2_PREFETCH10, "Pre-Fetch (10)"},
    {SCSI_SBC2_PREFETCH16, "Pre-Fetch (16)"},
    {SCSI_SBC2_READ6         , "Read (6)"},
    {SCSI_SBC2_READ10        , "Read (10)"},
    {SCSI_SBC2_READ12        , "Read (12)"},
    {SCSI_SBC2_READ16        , "Read (16)"},
    {SCSI_SBC2_READCAPACITY  , "Read Capacity"},
    {SCSI_SBC2_READDEFDATA10 , "Read Defect Data (10)"},
    {SCSI_SBC2_READDEFDATA12 , "Read Defect Data (12)"},
    {SCSI_SBC2_READLONG, "Read Long"},
    {SCSI_SBC2_REASSIGNBLKS  , "Reassign Blocks"},
    {SCSI_SBC2_REBUILD16, "Rebuild (16)"},
    {SCSI_SBC2_REBUILD32, "Rebuild (32)"},
    {SCSI_SBC2_REGENERATE16, "Regenerate (16)"},
    {SCSI_SBC2_REGENERATE32, "Regenerate (32)"},
    {SCSI_SBC2_SEEK10, "Seek (10)"},
    {SCSI_SBC2_SETLIMITS10, "Set Limits (10)"},
    {SCSI_SBC2_SETLIMITS12, "Set Limits (12)"},
    {SCSI_SBC2_STARTSTOPUNIT, "Start Stop Unit"},
    {SCSI_SBC2_SYNCCACHE10, "Synchronize Cache (10)"},
    {SCSI_SBC2_SYNCCACHE16, "Synchronize Cache (16)"},
    {SCSI_SBC2_VERIFY10, "Verify (10)"},
    {SCSI_SBC2_VERIFY12, "Verify (12)"},
    {SCSI_SBC2_VERIFY16, "Verify (16)"},
    {SCSI_SBC2_WRITE6        , "Write (6)"},
    {SCSI_SBC2_WRITE10       , "Write (10)"},
    {SCSI_SBC2_WRITE12       , "Write (12)"},
    {SCSI_SBC2_WRITE16       , "Write (16)"},
    {SCSI_SBC2_WRITENVERIFY10, "Write & Verify (10)"},
    {SCSI_SBC2_WRITENVERIFY12, "Write & Verify (12)"},
    {SCSI_SBC2_WRITENVERIFY16, "Write & Verify (16)"},
    {SCSI_SBC2_WRITELONG, "Write Long"},
    {SCSI_SBC2_WRITESAME10, "Write Same (10)"},
    {SCSI_SBC2_WRITESAME16, "Write Same (16)"},
    {SCSI_SBC2_XDREAD10, "XdRead (10)"},
    {SCSI_SBC2_XDREAD32, "XdRead (32)"},
    {SCSI_SBC2_XDWRITE10, "XdWrite (10)"},
    {SCSI_SBC2_XDWRITE32, "XdWrite(32)"},
    {SCSI_SBC2_XDWRITEREAD10, "XdWriteRead (10)"},
    {SCSI_SBC2_XDWRITEREAD32, "XdWriteRead (32)"},
    {SCSI_SBC2_XDWRITEEXTD16, "XdWrite Extended (16)"},
    {SCSI_SBC2_XDWRITEEXTD32, "XdWrite Extended (32)"},
    {SCSI_SBC2_XPWRITE10, "XpWrite (10)"},
    {SCSI_SBC2_XPWRITE32, "XpWrite (32)"},
    {0, NULL},
};

/* SSC2 Commands */
#define SCSI_SSC2_ERASE_16                      0x93
#define SCSI_SSC2_FORMAT_MEDIUM                 0x04
#define SCSI_SSC2_LOAD_UNLOAD                   0x1B
#define SCSI_SSC2_LOCATE_16                     0x92
#define SCSI_SSC2_MOVE_MEDIUM                   0xA5
#define SCSI_SSC2_MOVE_MEDIUM_ATTACHED          0xA7
#define SCSI_SSC2_READ_16                       0x88
#define SCSI_SSC2_READ_BLOCK_LIMITS             0x05
#define SCSI_SSC2_READ_ELEMENT_STATUS           0xB8
#define SCSI_SSC2_READ_ELEMENT_STATUS_ATTACHED  0xB4
#define SCSI_SSC2_READ_POSITION                 0x34
#define SCSI_SSC2_READ_REVERSE_16               0x81
#define SCSI_SSC2_RECOVER_BUFFERED_DATA         0x14
#define SCSI_SSC2_REPORT_DENSITY_SUPPORT        0x44
#define SCSI_SSC2_REWIND                        0x01
#define SCSI_SSC2_SET_CAPACITY                  0x0B
#define SCSI_SSC2_SPACE_16                      0x91
#define SCSI_SSC2_VERIFY_16                     0x8F
#define SCSI_SSC2_WRITE_16                      0x8A
#define SCSI_SSC2_WRITE_FILEMARKS_16            0x80
#define SCSI_SSC2_ERASE_6                       0x19
#define SCSI_SSC2_LOCATE_10                     0x2B
#define SCSI_SSC2_LOCATE_16                     0x92
#define SCSI_SSC2_READ_6                        0x08
#define SCSI_SSC2_READ_REVERSE_6                0x0F
#define SCSI_SSC2_SPACE_6                       0x11
#define SCSI_SSC2_VERIFY_6                      0x13
#define SCSI_SSC2_WRITE_6                       0x0A
#define SCSI_SSC2_WRITE_FILEMARKS_6             0x10

static const value_string scsi_ssc2_val[] = {
    {SCSI_SSC2_ERASE_16                    , "Erase(16)"},
    {SCSI_SSC2_FORMAT_MEDIUM               , "Format Medium"},
    {SCSI_SSC2_LOAD_UNLOAD                 , "Load Unload"},
    {SCSI_SSC2_LOCATE_16                   , "Locate(16)"},
    {SCSI_SSC2_MOVE_MEDIUM                 , "Move Medium"},
    {SCSI_SSC2_MOVE_MEDIUM_ATTACHED        , "Move Medium Attached"},
    {SCSI_SSC2_READ_16                     , "Read(16)"},
    {SCSI_SSC2_READ_BLOCK_LIMITS           , "Read Block Limits"},
    {SCSI_SSC2_READ_ELEMENT_STATUS         , "Read Element Status"},
    {SCSI_SSC2_READ_ELEMENT_STATUS_ATTACHED, "Read Element Status Attached"},
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
    {SCSI_SSC2_READ_6                      , "Read(6)"},
    {SCSI_SSC2_READ_REVERSE_6              , "Read Reverse(6)"},
    {SCSI_SSC2_SPACE_6                     , "Space(6)"},
    {SCSI_SSC2_VERIFY_6                    , "Verify(6)"},
    {SCSI_SSC2_WRITE_6                     , "Write(6)"},
    {SCSI_SSC2_WRITE_FILEMARKS_6           , "Write Filemarks(6)"},
};

static const value_string scsi_evpd_pagecode_val[] = {
    {0x00, "Supported Vital Data Product Pages"},
    {0x80, "Unit Serial Number Page"},
    {0x82, "ASCII Implemented Operating Definition Page"},
    {0x01, "ASCII Information Page"},
    {0x02, "ASCII Information Page"},
    {0x03, "ASCII Information Page"},
    {0x04, "ASCII Information Page"},
    {0x05, "ASCII Information Page"},
    {0x06, "ASCII Information Page"},
    {0x07, "ASCII Information Page"},
    {0x83, "Device Identification Page"},
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

#define SCSI_MODEPAGE_VEND          0x0
#define SCSI_MODEPAGE_CTL           0x0A
#define SCSI_MODEPAGE_DISCON        0x02
#define SCSI_MODEPAGE_INFOEXCP      0x1C
#define SCSI_MODEPAGE_PWR           0x1A
#define SCSI_MODEPAGE_LUN           0x18
#define SCSI_MODEPAGE_PORT          0x19
#define SCSI_MODEPAGE_RDWRERR       0x01
#define SCSI_MODEPAGE_FMTDEV        0x03
#define SCSI_MODEPAGE_DISKGEOM      0x04
#define SCSI_MODEPAGE_FLEXDISK      0x05
#define SCSI_MODEPAGE_VERERR        0x07
#define SCSI_MODEPAGE_CACHE         0x08
#define SCSI_MODEPAGE_PERDEV        0x09
#define SCSI_MODEPAGE_MEDTYPE       0x0B
#define SCSI_MODEPAGE_NOTPART       0x0C
#define SCSI_MODEPAGE_XORCTL        0x10

static const value_string scsi_modesns_page_val[] = {
    {0, "Vendor Specific Page"},
    {0x0A, "Control"},
    {0x02, "Disconnect-Reconnect"},
    {0x1C, "Informational Exceptions Control"},
    {0x1A, "Power Condition"},
    {0x18, "Protocol Specific LUN"},
    {0x19, "Protocol-Specific Port"},
    {0x01, "Read/Write Error Recovery"},
    {0x03, "Format Device"},
    {0x04, "Rigid Disk Geometry"},
    {0x05, "Flexible Disk"},
    {0x07, "Verify Error Recovery"},
    {0x08, "Caching"},
    {0x09, "Peripheral Device"},
    {0x0B, "Medium Types Supported"},
    {0x0C, "Notch & Partition"},
    {0x10, "XOR Control"},
    {0x3F, "Return All Mode Pages"},
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

/* SCSI Device Types */
#define SCSI_DEV_SBC       0x0
#define SCSI_DEV_SSC       0x1
#define SCSI_DEV_PRNT      0x2
#define SCSI_DEV_PROC      0x3
#define SCSI_DEV_WORM      0x4
#define SCSI_DEV_CDROM     0x5
#define SCSI_DEV_SCAN      0x6
#define SCSI_DEV_OPTMEM    0x7
#define SCSI_DEV_SMC       0x8
#define SCSI_DEV_COMM      0x9
#define SCSI_DEV_RAID      0xC
#define SCSI_DEV_SES       0xD
#define SCSI_DEV_RBC       0xE
#define SCSI_DEV_OCRW      0xF
#define SCSI_DEV_OSD       0x11

static const value_string scsi_devtype_val[] = {
    {SCSI_DEV_SBC   , "Direct Access Device"},
    {SCSI_DEV_SSC   , "Sequential Access Device"},
    {SCSI_DEV_PRNT  , "Printer"},
    {SCSI_DEV_PROC  , "Processor"},
    {SCSI_DEV_WORM  , "WORM"},
    {SCSI_DEV_CDROM , "CD ROM"},
    {SCSI_DEV_SCAN  , "Scanner"},
    {SCSI_DEV_OPTMEM, "Optical Memory"},
    {SCSI_DEV_SMC   , "Medium Changer"},
    {SCSI_DEV_COMM  , "Communication"},
    {SCSI_DEV_RAID  , "Storage Array"},
    {SCSI_DEV_SES   , "Enclosure Services"},
    {SCSI_DEV_RBC   , "Simplified Block Device"},
    {SCSI_DEV_OCRW  , "OCRW"},
    {SCSI_DEV_OSD   , "OSD"},
    {0, NULL},
};

static const enum_val_t scsi_devtype_options[] = {
    {"Block Device", SCSI_DEV_SBC},
    {"Sequential Device", SCSI_DEV_SSC},
    {NULL, -1},
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

static const value_string scsi_modesense_medtype_val[] = {
    {0, "Default"},
    {1, "Flexible Disk, Single-sided"},
    {2, "Flexible Disk, Double-sided"},
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

#define SCSI_EVPD_SUPPPG          0
#define SCSI_EVPD_ASCIIOPER       0x82
#define SCSI_EVPD_DEVID           0x83
#define SCSI_EVPD_DEVSERNUM       0x80

static const value_string scsi_inq_evpd_val[] = {
    {SCSI_EVPD_SUPPPG, "Supported Vital Product Data Page"},
    {SCSI_EVPD_ASCIIOPER, "ASCII Implemented Operating Definition Page"},
    {SCSI_EVPD_DEVID, "Device ID Page"},
    {SCSI_EVPD_DEVSERNUM, "Unit Serial Number Page"},
    {0x0, NULL},
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

static const value_string scsi_devid_codeset_val[] = {
    {0, "Reserved"},
    {1, "Identifier field contains binary values"},
    {2, "Identifier field contains ASCII graphic codes"},
    {0, NULL},
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

static gint scsi_def_devtype = SCSI_DEV_SBC;

/*
 * We track SCSI requests and responses with a hash table.
 * The key is a "scsi_task_id_t" structure; the data is a
 * "scsi_task_data_t" structure.
 */
typedef struct _scsi_task_data {
    guint32 opcode;
    scsi_device_type devtype;
    guint8 flags;               /* used by SCSI Inquiry */
} scsi_task_data_t;

/* The next two data structures are used to track SCSI device type */
typedef struct _scsi_devtype_key {
    address devid;
} scsi_devtype_key_t;

typedef struct _scsi_devtype_data {
    scsi_device_type devtype;
} scsi_devtype_data_t;

static GHashTable *scsi_req_hash = NULL;
static GMemChunk *scsi_req_keys = NULL;
static GMemChunk *scsi_req_vals = NULL;
static guint32 scsi_init_count = 25;

static GHashTable *scsidev_req_hash = NULL;
static GMemChunk *scsidev_req_keys = NULL;
static GMemChunk *scsidev_req_vals = NULL;
static guint32 scsidev_init_count = 25;

static dissector_handle_t data_handle;

/*
 * Hash Functions
 */
static gint
scsi_equal(gconstpointer v, gconstpointer w)
{
  scsi_task_id_t *v1 = (scsi_task_id_t *)v;
  scsi_task_id_t *v2 = (scsi_task_id_t *)w;

  return (v1->conv_id == v2->conv_id && v1->task_id == v2->task_id);
}

static guint
scsi_hash (gconstpointer v)
{
	scsi_task_id_t *key = (scsi_task_id_t *)v;
	guint val;

	val = key->conv_id + key->task_id;

	return val;
}

static gint
scsidev_equal (gconstpointer v, gconstpointer w)
{
    scsi_devtype_key_t *k1 = (scsi_devtype_key_t *)v;
    scsi_devtype_key_t *k2 = (scsi_devtype_key_t *)w;

    if (ADDRESSES_EQUAL (&k1->devid, &k2->devid))
        return 1;
    else
        return 0;
}

static guint
scsidev_hash (gconstpointer v)
{
    scsi_devtype_key_t *key = (scsi_devtype_key_t *)v;
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
    conversation_t *conversation;
    
    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey = *(scsi_task_id_t *)pinfo->private_data;

        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
        if (!cdata) {
            req_key = g_mem_chunk_alloc (scsi_req_keys);
            *req_key = *(scsi_task_id_t *)pinfo->private_data;
            
            cdata = g_mem_chunk_alloc (scsi_req_vals);
            
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
    conversation_t *conversation;

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
    conversation_t *conversation;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey = *(scsi_task_id_t *)pinfo->private_data;
        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
        if (cdata) {
            g_mem_chunk_free (scsi_req_vals, cdata);
            g_hash_table_remove (scsi_req_hash, &ckey);
        }
    }
}

/*
 * Protocol initialization
 */
static void
scsi_init_protocol(void)
{
	if (scsi_req_keys)
            g_mem_chunk_destroy(scsi_req_keys);
	if (scsi_req_vals)
            g_mem_chunk_destroy(scsi_req_vals);
        if (scsidev_req_keys)
            g_mem_chunk_destroy (scsidev_req_keys);
        if (scsidev_req_vals)
            g_mem_chunk_destroy (scsidev_req_vals);
	if (scsi_req_hash)
            g_hash_table_destroy(scsi_req_hash);
        if (scsidev_req_hash)
            g_hash_table_destroy (scsidev_req_hash);

	scsi_req_hash = g_hash_table_new(scsi_hash, scsi_equal);
	scsi_req_keys = g_mem_chunk_new("scsi_req_keys",
                                        sizeof(scsi_task_id_t),
                                        scsi_init_count *
                                        sizeof(scsi_task_id_t),
                                        G_ALLOC_AND_FREE);
	scsi_req_vals = g_mem_chunk_new("scsi_req_vals",
                                        sizeof(scsi_task_data_t),
                                        scsi_init_count *
                                        sizeof(scsi_task_data_t),
                                        G_ALLOC_AND_FREE);
        scsidev_req_hash = g_hash_table_new (scsidev_hash, scsidev_equal);
        scsidev_req_keys = g_mem_chunk_new("scsidev_req_keys",
                                           sizeof(scsi_devtype_key_t),
                                           scsidev_init_count *
                                           sizeof(scsi_devtype_key_t),
                                           G_ALLOC_AND_FREE);
        scsidev_req_vals = g_mem_chunk_new("scsidev_req_vals",
                                           sizeof(scsi_devtype_data_t),
                                           scsidev_init_count *
                                           sizeof(scsi_devtype_data_t),
                                           G_ALLOC_AND_FREE);
}

static void
dissect_scsi_evpd (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   guint offset, guint tot_len)
{
    proto_tree *evpd_tree;
    proto_item *ti;
    guint pcode, plen, i, idlen;
    guint8 flags;
    char str[32];

    if (tree) {
        pcode = tvb_get_guint8 (tvb, offset+1);
        plen = tvb_get_guint8 (tvb, offset+3);
        ti = proto_tree_add_text (tree, tvb, offset, plen+4, "Page Code: %s",
                                  val_to_str (pcode, scsi_evpd_pagecode_val,
                                              "Unknown (0x%08x)"));
        evpd_tree = proto_item_add_subtree (ti, ett_scsi_page);
        
        proto_tree_add_text (evpd_tree, tvb, offset, 1,
                             "Peripheral Qualifier: 0x%x",
                             (tvb_get_guint8 (tvb, offset) & 0xF0)>>4);
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
            while (plen > 0) {
                flags = tvb_get_guint8 (tvb, offset);
                proto_tree_add_text (evpd_tree, tvb, offset, 1,
                                     "Code Set: %s",
                                     val_to_str (plen & 0x0F,
                                                 scsi_devid_codeset_val,
                                                 "Unknown (0x%02x)"));
                flags = tvb_get_guint8 (tvb, offset+1);
                proto_tree_add_text (evpd_tree, tvb, offset+1, 1,
                                     "Association: %s",
                                     val_to_str ((flags & 0x30) >> 4,
                                                 scsi_devid_assoc_val,
                                                 "Unknown (0x%02x)"));
                proto_tree_add_text (evpd_tree, tvb, offset+1, 1,
                                     "Identifier Type: %s", 
                                     val_to_str ((flags & 0x0F),
                                                 scsi_devid_idtype_val, 
                                                 "Unknown (0x%02x)"));
                idlen = tvb_get_guint8 (tvb, offset+3);
                proto_tree_add_text (evpd_tree, tvb, offset+3, 1,
                                     "Identifier Length: %u", idlen);
                proto_tree_add_text (evpd_tree, tvb, offset+4, idlen,
                                         "Identifier: %s",
                                         tvb_bytes_to_str (tvb, offset+4,
                                                           idlen));
                plen -= idlen;
                offset += idlen;
            }
            break;
        case SCSI_EVPD_DEVSERNUM:
            str[0] = '\0';
            tvb_get_nstringz0 (tvb, offset, plen, str);
            proto_tree_add_text (evpd_tree, tvb, offset, plen,
                                 "Product Serial Number: %s", str);
            break;
        }
    }
}

static void
dissect_scsi_cmddt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint offset, guint tot_len)
{
    proto_tree *cmdt_tree;
    proto_item *ti;
    guint opcode, plen, i;
    guint8 flags;

    if (tree) {
        plen = tvb_get_guint8 (tvb, offset+5);
        ti = proto_tree_add_text (tree, tvb, offset, plen, "Command Data");
        cmdt_tree = proto_item_add_subtree (ti, ett_scsi_page);

        proto_tree_add_text (cmdt_tree, tvb, offset, 1,
                             "Peripheral Qualifier: 0x%x",
                             (tvb_get_guint8 (tvb, offset) & 0xF0)>>4);
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

void
dissect_scsi_inquiry (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint32 payload_len, scsi_task_data_t *cdata)
{
    guint8 flags, i;
    gchar str[32];
    guint tot_len, pcode, plen, replen;
    conversation_t *conversation;
    scsi_device_type dev = 0;
    scsi_devtype_data_t *devdata = NULL;
    scsi_devtype_key_t dkey, *req_key;

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

        proto_tree_add_uint (tree, hf_scsi_alloclen, tvb, offset+3, 1, 0);
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

        /* Add device type to list of known devices & their types */
        COPY_ADDRESS (&(dkey.devid), &(pinfo->src));
        devdata = (scsi_devtype_data_t *)g_hash_table_lookup (scsidev_req_hash,
                                                              &dkey);
        if (!devdata) {
            req_key = g_mem_chunk_alloc (scsidev_req_keys);
            COPY_ADDRESS (&(req_key->devid), &(pinfo->src));

            devdata = g_mem_chunk_alloc (scsidev_req_vals);
            devdata->devtype = tvb_get_guint8 (tvb, offset) & 0x10;

            g_hash_table_insert (scsidev_req_hash, req_key, devdata);
        }
        
        proto_tree_add_text (tree, tvb, offset, 1, "Peripheral Qualifier: 0x%x",
                             (tvb_get_guint8 (tvb, offset) & 0xF0)>>4);
        proto_tree_add_item (tree, hf_scsi_inq_devtype, tvb, offset, 1, 0);
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
                             (flags & 10) >> 4, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "RelAdr: %u, Linked: %u, CmdQue: %u",
                             (flags & 0x80) >> 7, (flags & 0x08) >> 3,
                             (flags & 0x02) >> 1);
        tvb_get_nstringz0 (tvb, offset+8, 8, str);
        proto_tree_add_text (tree, tvb, offset+8, 8, "Vendor Id: %s", str);
        tvb_get_nstringz0 (tvb, offset+16, 16, str);
        proto_tree_add_text (tree, tvb, offset+16, 16, "Product ID: %s", str);
        tvb_get_nstringz0 (tvb, offset+32, 4, str);
        proto_tree_add_text (tree, tvb, offset+32, 4, "Product Revision: %s",
                             str);
        
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
dissect_scsi_extcopy (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb)
{
    
}

static void
dissect_scsi_logselect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;
    
    if (!tree)
        return;
    
    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        
        proto_tree_add_uint_format (tree, hf_scsi_logsel_flags, tvb, offset, 1,
                                    flags, "PCR = %u, SP = %u", flags & 0x2,
                                    flags & 0x1);
        proto_tree_add_uint_format (tree, hf_scsi_log_pc, tvb, offset+1, 1,
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
dissect_scsi_logsense (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;
    
    if (!tree)
        return;
    
    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        
        proto_tree_add_uint_format (tree, hf_scsi_logsns_flags, tvb, offset, 1,
                                    flags, "PPC = %u, SP = %u", flags & 0x2,
                                    flags & 0x1);
        proto_tree_add_uint_format (tree, hf_scsi_log_pc, tvb, offset+1, 1,
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

static guint8
dissect_scsi_modepage (tvbuff_t *tvb, packet_info *pinfo, proto_tree *scsi_tree,
                       guint offset)
{
    guint8 pcode, plen, flags, proto;
    proto_tree *tree;
    proto_item *ti;

    pcode = tvb_get_guint8 (tvb, offset);
    plen = tvb_get_guint8 (tvb, offset+1);

    ti = proto_tree_add_text (scsi_tree, tvb, offset, plen+2, "%s Mode Page",
                              val_to_str (pcode & 0x3F, scsi_modesns_page_val,
                                          "Unknown (0x%08x)"));
    tree = proto_item_add_subtree (ti, ett_scsi_page);
    proto_tree_add_text (tree, tvb, offset, 1, "PS: %u", (pcode & 0x80) >> 8);
                         
    proto_tree_add_item (tree, hf_scsi_modesns_pagecode, tvb, offset, 1, 0);
    proto_tree_add_text (tree, tvb, offset+1, 1, "Page Length: %u",
                         plen);

    if (!tvb_bytes_exist (tvb, offset, plen)) {
        return (plen + 2);
    }
    
    pcode &= 0x3F;
    switch (pcode) {
    case SCSI_MODEPAGE_CTL:
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
    case SCSI_MODEPAGE_DISCON:
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
    case SCSI_MODEPAGE_INFOEXCP:
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
    case SCSI_MODEPAGE_PWR:
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
    case SCSI_MODEPAGE_LUN:
        break;
    case SCSI_MODEPAGE_PORT:
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
        }
        else {
        }
        break;
    case SCSI_MODEPAGE_FMTDEV:
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
    case SCSI_MODEPAGE_RDWRERR:
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
    case SCSI_MODEPAGE_DISKGEOM:
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
    case SCSI_MODEPAGE_FLEXDISK:
        break;
    case SCSI_MODEPAGE_VERERR:
        break;
    case SCSI_MODEPAGE_CACHE:
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
    case SCSI_MODEPAGE_PERDEV:
        break;
    case SCSI_MODEPAGE_MEDTYPE:
        break;
    case SCSI_MODEPAGE_NOTPART:
        break;
    case SCSI_MODEPAGE_XORCTL:
        break;
    default:
        proto_tree_add_text (tree, tvb, offset, plen,
                             "Unknown Page");
        break;
    }
    return (plen+2);
}

static void
dissect_scsi_modeselect6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len)
{
    guint8 flags, pcode;
    guint tot_len, desclen, plen;
    
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
        tot_len = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1, "Mode Data Length: %u",
                             tot_len);
        proto_tree_add_text (tree, tvb, offset+1, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset+2));
        desclen = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Block Descriptor Length: %u", desclen);
        offset = 4;
        tot_len -= 3;           /* tot_len does not include the len field */
        if (desclen) {
            proto_tree_add_text (tree, tvb, offset, 4, "No. of Blocks: %u",
                                 tvb_get_ntohl (tvb, offset));
            proto_tree_add_text (tree, tvb, offset+4, 1, "Density Code: 0x%02x",
                                 tvb_get_guint8 (tvb, offset+4));
            proto_tree_add_text (tree, tvb, offset+5, 3, "Block Length: %u",
                                 tvb_get_ntoh24 (tvb, offset+5));
            offset += 8;        /* increment the offset by 8 */
            tot_len -= 8;       /* subtract by the block desc len */
        }
        /* offset points to the start of the mode page */
        while ((tot_len > offset) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset);
            offset += plen;
        }
    }
}

static void
dissect_scsi_modeselect10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len)
{
    guint8 flags, pcode;
    gboolean longlba;
    guint tot_len, desclen, plen;
    
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
        tot_len = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 2, "Mode Data Length: %u",
                             tot_len);
        proto_tree_add_text (tree, tvb, offset+2, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset+2));
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset+3));
        longlba = tvb_get_guint8 (tvb, offset+4) & 0x1;
        proto_tree_add_text (tree, tvb, offset+4, 1, "LongLBA: %u", longlba);
        desclen = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "Block Descriptor Length: %u", desclen);
        offset = 8;
        tot_len -= 6;           /* tot_len does not include the len field */
        if (desclen) {
            proto_tree_add_text (tree, tvb, offset, 8, "No. of Blocks: %s",
                                 bytes_to_str (tvb_get_ptr (tvb, offset, 8),
                                               8));
            proto_tree_add_text (tree, tvb, offset+8, 1, "Density Code: 0x%02x",
                                 tvb_get_guint8 (tvb, offset+4));
            proto_tree_add_text (tree, tvb, offset+12, 4, "Block Length: %u",
                                 tvb_get_ntohl (tvb, offset+12));
            offset += 16;        /* increment the offset by 8 */
            tot_len -= 16;       /* subtract by the block desc len */
        }
        /* offset points to the start of the mode page */
        while ((tot_len > offset) && tvb_bytes_exist (tvb, offset, 2)) {
            offset += dissect_scsi_modepage (tvb, pinfo, tree, offset);
        }
    }
}

static void
dissect_scsi_modesense6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len)
{
    guint8 flags, pcode;
    guint tot_len, desclen, plen;
    
    if (!tree)
        return;
    
    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        
        proto_tree_add_uint_format (tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                    flags, "DBD = %u", flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_modesns_pc, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_modesns_pagecode, tvb, offset+1, 1,
                             0);
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
        proto_tree_add_text (tree, tvb, offset+1, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset+2));
        desclen = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Block Descriptor Length: %u", desclen);
        offset = 4;
        /* The actual payload is the min of the length in the response & the
         * space allocated by the initiator as specified in the request.
         */
        if (payload_len && (tot_len > payload_len))
            tot_len = payload_len;
        if (desclen) {
            proto_tree_add_text (tree, tvb, offset, 4, "No. of Blocks: %u",
                                 tvb_get_ntohl (tvb, offset));
            proto_tree_add_text (tree, tvb, offset+4, 1, "Density Code: 0x%02x",
                                 tvb_get_guint8 (tvb, offset+4));
            proto_tree_add_text (tree, tvb, offset+5, 3, "Block Length: %u",
                                 tvb_get_ntoh24 (tvb, offset+5));
            offset += 8;        /* increment the offset by 8 */
        }
        /* offset points to the start of the mode page */
        while ((tot_len > offset) && tvb_bytes_exist (tvb, offset, 2)) {
            plen = dissect_scsi_modepage (tvb, pinfo, tree, offset);
            offset += plen;
        }
    }
}

static void
dissect_scsi_modesense10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          guint payload_len)
{
    guint8 flags, pcode;
    gboolean longlba;
    guint tot_len, desclen, plen;
 
    if (!tree)
        return;
    
    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        
        proto_tree_add_uint_format (tree, hf_scsi_modesns_flags, tvb, offset, 1,
                                    flags, "LLBAA = %u, DBD = %u", flags & 0x10,
                                    flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_modesns_pc, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_scsi_modesns_pagecode, tvb, offset+1, 1,
                             0);
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
        proto_tree_add_text (tree, tvb, offset+2, 1, "Medium Type: 0x%02x",
                             tvb_get_guint8 (tvb, offset+2));
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Device-Specific Parameter: 0x%02x",
                             tvb_get_guint8 (tvb, offset+3));
        longlba = tvb_get_guint8 (tvb, offset+4) & 0x1;
        proto_tree_add_text (tree, tvb, offset+4, 1, "LongLBA: %u", longlba);
        desclen = tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_text (tree, tvb, offset+6, 1,
                             "Block Descriptor Length: %u", desclen);
        offset = 8;
        tot_len -= 6;           /* tot_len does not include the len field */
        if (desclen) {
            proto_tree_add_text (tree, tvb, offset, 8, "No. of Blocks: %s",
                                 bytes_to_str (tvb_get_ptr (tvb, offset, 8),
                                               8));
            proto_tree_add_text (tree, tvb, offset+8, 1, "Density Code: 0x%02x",
                                 tvb_get_guint8 (tvb, offset+4));
            proto_tree_add_text (tree, tvb, offset+12, 4, "Block Length: %u",
                                 tvb_get_ntohl (tvb, offset+12));
            offset += 16;        /* increment the offset by 8 */
            tot_len -= 16;       /* subtract by the block desc len */
        }
        /* offset points to the start of the mode page */
        while ((tot_len > offset) && tvb_bytes_exist (tvb, offset, 2)) {
            offset += dissect_scsi_modepage (tvb, pinfo, tree, offset);
        }
    }
}

static void
dissect_scsi_persresvin (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         scsi_task_data_t *cdata, guint payload_len)
{
    guint8 flags;
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
dissect_scsi_persresvout (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb,
                          scsi_task_data_t *cdata, guint payload_len)
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
dissect_scsi_release6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_release10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_reportdeviceid (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset, gboolean isreq, gboolean iscdb)
{
    
}

static void
dissect_scsi_reportluns (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;
    guint numelem, i;

    if (!tree)
        return;
    
    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_alloclen32, tvb, offset+5, 4, 0);

        flags = tvb_get_guint8 (tvb, offset+10);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+10, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    else if (!isreq) {
        numelem = tvb_get_ntohl (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 4, "LUN List Length: %u",
                             numelem);
        offset += 8;
        for (i = 0; i < numelem/8; i++) {
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
dissect_scsi_reqsense (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb)
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
}

static void
dissect_scsi_reserve6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_reserve10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_testunitrdy (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_formatunit (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_rdwr6 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;

    if (isreq) {
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
dissect_scsi_rdwr10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;

    if (isreq) {
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
dissect_scsi_rdwr12 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;

    if (isreq) {
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
dissect_scsi_rdwr16 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;

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
dissect_scsi_readcapacity (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;
    guint len;

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
        proto_tree_add_text (tree, tvb, offset, 4, "LBA: %u (%u MB)",
                             len, len/(1024*1024));
        proto_tree_add_text (tree, tvb, offset+4, 4, "Block Length: %u bytes",
                             tvb_get_ntohl (tvb, offset+4));
    }
}

static void
dissect_scsi_readdefdata10 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_readdefdata12 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_reassignblks (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb)
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
dissect_scsi_varlencdb (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb)
{
    guint8 flags;

    if (!tree)
        return;
    
    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_control, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_add_cdblen, tvb, offset+6, 1, 0);
        proto_tree_add_item (tree, hf_scsi_svcaction, tvb, offset+7, 2, 0);
    }
}

void
dissect_scsi_rsp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Nothing to do here, just blow up the data structures for this SCSI
     * transaction
    if (tree)
        scsi_end_task (pinfo);
     */
}

void
dissect_scsi_snsinfo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, guint snslen)
{
    guint8 flags;
    proto_item *ti;
    proto_tree *sns_tree;
    scsi_device_type dev = 0;
    scsi_devtype_key_t dkey;
    scsi_devtype_data_t *devdata;

    scsi_end_task (pinfo);
    
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                             snslen, "SCSI: SNS Info");
        sns_tree = proto_item_add_subtree (ti, ett_scsi);

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
}

void
dissect_scsi_cdb (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  guint start, guint cdblen)
{
    int offset = start;
    proto_item *ti;
    proto_tree *scsi_tree = NULL;
    guint8 opcode;
    scsi_cmnd_type cmd = 0;     /* 0 is undefined type */
    scsi_device_type devtype = 0;
    gchar *valstr;
    conversation_t *conversation;
    scsi_task_data_t *cdata;
    scsi_devtype_key_t dkey;
    scsi_devtype_data_t *devdata;
    
    opcode = tvb_get_guint8 (tvb, offset);

    /* Identify target if possible */
    COPY_ADDRESS (&(dkey.devid), &pinfo->dst);

    devdata = (scsi_devtype_data_t *)g_hash_table_lookup (scsidev_req_hash,
                                                          &dkey);
    if (devdata != NULL) {
        devtype = devdata->devtype;
    }
    else {
        devtype = (scsi_device_type)scsi_def_devtype;
    }

    if ((valstr = match_strval (opcode, scsi_spc2_val)) == NULL) {
        if (devtype == SCSI_DEV_SBC) {
            valstr = match_strval (opcode, scsi_sbc2_val);
            cmd = SCSI_CMND_SBC2;
        }
        else {
            /* Right now, the only choices are SBC or SSC. If we ever expand
             * this to decode other device types, this piece of code needs to
             * be modified.
             */
            valstr = match_strval (opcode, scsi_ssc2_val);
            cmd = SCSI_CMND_SSC2;
        }
    }
    else {
        cmd = SCSI_CMND_SPC2;
    }
    
    if (valstr != NULL) {
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI: %s", valstr);
        }
    }
    else {
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "SCSI Command: 0x%02x", opcode);
        }
    }

    cdata = scsi_new_task (pinfo);

    if (cdata) {
        cdata->opcode = opcode;
        cdata->devtype = cmd;
    }
    
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, start,
                                             cdblen, "SCSI CDB");
        scsi_tree = proto_item_add_subtree (ti, ett_scsi);

        if (valstr != NULL) {
            if (cmd == SCSI_CMND_SPC2) {
                proto_tree_add_uint_format (scsi_tree, hf_scsi_spcopcode, tvb,
                                            offset, 1,
                                            tvb_get_guint8 (tvb, offset),
                                            "Opcode: %s (0x%02x)", valstr,
                                            opcode);
            }
            else if (cmd == SCSI_CMND_SBC2) {
                proto_tree_add_uint_format (scsi_tree, hf_scsi_sbcopcode, tvb,
                                            offset, 1,
                                            tvb_get_guint8 (tvb, offset),
                                            "Opcode: %s (0x%02x)", valstr,
                                            opcode);
            }
            else {
                 proto_tree_add_uint_format (scsi_tree, hf_scsi_sscopcode, tvb,
                                             offset, 1,
                                             tvb_get_guint8 (tvb, offset),
                                             "Opcode: %s (0x%02x)", valstr,
                                             opcode);
            }
        }
        else {
            proto_tree_add_item (scsi_tree, hf_scsi_sbcopcode, tvb, offset, 1, 0);
        }
    }
        
    if (cmd == SCSI_CMND_SPC2) {
        switch (opcode) {
        case SCSI_SPC2_INQUIRY:
            dissect_scsi_inquiry (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                  TRUE, 0, cdata);
            break;

        case SCSI_SPC2_EXTCOPY:
            dissect_scsi_extcopy (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                  TRUE);
            break;

        case SCSI_SPC2_LOGSELECT:
            dissect_scsi_logselect (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                    TRUE);
            break;

        case SCSI_SPC2_LOGSENSE:
            dissect_scsi_logsense (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                   TRUE);
            break;

        case SCSI_SPC2_MODESELECT6:
            dissect_scsi_modeselect6 (tvb, pinfo, scsi_tree, offset+1,
                                      TRUE, TRUE, 0);
            break;

        case SCSI_SPC2_MODESELECT10:
            dissect_scsi_modeselect10 (tvb, pinfo, scsi_tree, offset+1,
                                       TRUE, TRUE, 0);
            break;

        case SCSI_SPC2_MODESENSE6:
            dissect_scsi_modesense6 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                     TRUE, 0);
            break;

        case SCSI_SPC2_MODESENSE10:
            dissect_scsi_modesense10 (tvb, pinfo, scsi_tree, offset+1,
                                      TRUE, TRUE, 0);
            break;

        case SCSI_SPC2_PERSRESVIN:
            dissect_scsi_persresvin (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                     TRUE, cdata, 0);
            break;

        case SCSI_SPC2_PERSRESVOUT:
            dissect_scsi_persresvout (tvb, pinfo, scsi_tree, offset+1,
                                      TRUE, TRUE, cdata, 0);
            break;

        case SCSI_SPC2_RELEASE6:
            dissect_scsi_release6 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                   TRUE);
            break;

        case SCSI_SPC2_RELEASE10:
            dissect_scsi_release10 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                    TRUE);
            break;

        case SCSI_SPC2_REPORTDEVICEID:
            dissect_scsi_reportdeviceid (tvb, pinfo, scsi_tree, offset+1,
                                         TRUE, TRUE);
            break;

        case SCSI_SPC2_REPORTLUNS:
            dissect_scsi_reportluns (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                     TRUE);
            break;

        case SCSI_SPC2_REQSENSE:
            dissect_scsi_reqsense (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                   TRUE);
            break;

        case SCSI_SPC2_RESERVE6:
            dissect_scsi_reserve6 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                   TRUE);
            break;

        case SCSI_SPC2_RESERVE10:
            dissect_scsi_reserve10 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                    TRUE);
            break;

        case SCSI_SPC2_TESTUNITRDY:
            dissect_scsi_testunitrdy (tvb, pinfo, scsi_tree, offset+1,
                                      TRUE, TRUE);
            break;

        case SCSI_SPC2_VARLENCDB:
            dissect_scsi_varlencdb (tvb, pinfo, scsi_tree, offset+1,
                                    TRUE, TRUE);
            break;

        default:
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
            break;
        }
    }
    else if (cmd == SCSI_CMND_SBC2) {
        switch (opcode) {

        case SCSI_SBC2_FORMATUNIT:
            dissect_scsi_formatunit (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                     TRUE);
            break;

        case SCSI_SBC2_READ6:
            dissect_scsi_rdwr6 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                TRUE);
            break;

        case SCSI_SBC2_READ10:
            dissect_scsi_rdwr10 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        case SCSI_SBC2_READ12:
            dissect_scsi_rdwr12 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        case SCSI_SBC2_READ16:
            dissect_scsi_rdwr16 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        case SCSI_SBC2_READCAPACITY:
            dissect_scsi_readcapacity (tvb, pinfo, scsi_tree, offset+1,
                                       TRUE, TRUE);
            break;

        case SCSI_SBC2_READDEFDATA10:
            dissect_scsi_readdefdata10 (tvb, pinfo, scsi_tree, offset+1,
                                        TRUE, TRUE);
            break;

        case SCSI_SBC2_READDEFDATA12:
            dissect_scsi_readdefdata12 (tvb, pinfo, scsi_tree, offset+1,
                                        TRUE, TRUE);
            break;

        case SCSI_SBC2_REASSIGNBLKS:
            dissect_scsi_reassignblks (tvb, pinfo, scsi_tree, offset+1,
                                       TRUE, TRUE);
            break;

        case SCSI_SBC2_WRITE6:
            dissect_scsi_rdwr6 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                TRUE);
            break;

        case SCSI_SBC2_WRITE10:
            dissect_scsi_rdwr10 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        case SCSI_SBC2_WRITE12:
            dissect_scsi_rdwr12 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        case SCSI_SBC2_WRITE16:
            dissect_scsi_rdwr16 (tvb, pinfo, scsi_tree, offset+1, TRUE,
                                 TRUE);
            break;

        default:
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
            break;
        }
    }
    else if (cmd == SCSI_CMND_SSC2) {
        call_dissector (data_handle, tvb, pinfo, scsi_tree);
    }
}

static void
dissect_scsi (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
}

void
dissect_scsi_payload (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, guint32 payload_len)
{
    proto_item *ti;
    proto_tree *scsi_tree;
    guint8 opcode = 0xFF;
    scsi_cmnd_type cmd = 0;     /* 0 is undefined type */
    gchar *valstr;
    scsi_device_type dev = 0;
    scsi_task_data_t *cdata = NULL;
    scsi_devtype_key_t dkey;
    scsi_devtype_data_t *devdata;
    
    cdata = scsi_find_task (pinfo);
    
    if (!cdata) {
        /* we have no record of this exchange and so we can't dissect the
         * payload
         */
        return;
    }

    opcode = cdata->opcode;
    cmd = cdata->devtype;
    
    if (tree) {
        if (cmd == SCSI_CMND_SPC2) {
            ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                                 payload_len,
                                                 "SCSI Payload (%s %s)",
                                                 val_to_str (opcode,
                                                             scsi_spc2_val,
                                                             "0x%02x"),
                                                 isreq ? "Request" : "Response");
        }
        else if (cmd == SCSI_CMND_SBC2) {
            ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                                 payload_len,
                                                 "SCSI Payload (%s %s)",
                                                 val_to_str (opcode,
                                                             scsi_sbc2_val,
                                                             "0x%02x"),
                                                 isreq ? "Request" : "Response");
        }
        else {
            ti = proto_tree_add_protocol_format (tree, proto_scsi, tvb, offset,
                                                 payload_len,
                                                 "SCSI Payload (0x%02x %s)",
                                                 opcode,
                                                 isreq ? "Request" : "Response");
        }

        scsi_tree = proto_item_add_subtree (ti, ett_scsi);

        if (cmd == SCSI_CMND_SPC2) {
            switch (opcode) {
            case SCSI_SPC2_INQUIRY:
                dissect_scsi_inquiry (tvb, pinfo, scsi_tree, offset, isreq,
                                      FALSE, payload_len, cdata);
                break;

            case SCSI_SPC2_EXTCOPY:
                dissect_scsi_extcopy (tvb, pinfo, scsi_tree, offset, isreq,
                                      FALSE);
                break;

            case SCSI_SPC2_LOGSELECT:
                dissect_scsi_logselect (tvb, pinfo, scsi_tree, offset, isreq,
                                        FALSE);
                break;

            case SCSI_SPC2_LOGSENSE:
                dissect_scsi_logsense (tvb, pinfo, scsi_tree, offset, isreq,
                                       FALSE);
                break;

            case SCSI_SPC2_MODESELECT6:
                dissect_scsi_modeselect6 (tvb, pinfo, scsi_tree, offset,
                                          isreq, FALSE, payload_len);
                break;

            case SCSI_SPC2_MODESELECT10:
                dissect_scsi_modeselect10 (tvb, pinfo, scsi_tree, offset,
                                           isreq, FALSE, payload_len);
                break;

            case SCSI_SPC2_MODESENSE6:
                dissect_scsi_modesense6 (tvb, pinfo, scsi_tree, offset, isreq,
                                         FALSE, payload_len);
                break;

            case SCSI_SPC2_MODESENSE10:
                dissect_scsi_modesense10 (tvb, pinfo, scsi_tree, offset,
                                          isreq, FALSE, payload_len);
                break;

            case SCSI_SPC2_PERSRESVIN:
                dissect_scsi_persresvin (tvb, pinfo, scsi_tree, offset, isreq,
                                         FALSE, cdata, payload_len);
                break;

            case SCSI_SPC2_PERSRESVOUT:
                dissect_scsi_persresvout (tvb, pinfo, scsi_tree, offset,
                                          isreq, FALSE, cdata, payload_len);
                break;

            case SCSI_SPC2_RELEASE6:
                dissect_scsi_release6 (tvb, pinfo, scsi_tree, offset, isreq,
                                       FALSE);
                break;

            case SCSI_SPC2_RELEASE10:
                dissect_scsi_release10 (tvb, pinfo, scsi_tree, offset, isreq,
                                        FALSE);
                break;

            case SCSI_SPC2_REPORTDEVICEID:
                dissect_scsi_reportdeviceid (tvb, pinfo, scsi_tree, offset,
                                             isreq, FALSE);
                break;

            case SCSI_SPC2_REPORTLUNS:
                dissect_scsi_reportluns (tvb, pinfo, scsi_tree, offset, isreq,
                                         FALSE);
                break;

            case SCSI_SPC2_REQSENSE:
                dissect_scsi_reqsense (tvb, pinfo, scsi_tree, offset, isreq,
                                       FALSE);
                break;

            case SCSI_SPC2_RESERVE6:
                dissect_scsi_reserve6 (tvb, pinfo, scsi_tree, offset, isreq,
                                       FALSE);
                break;

            case SCSI_SPC2_RESERVE10:
                dissect_scsi_reserve10 (tvb, pinfo, scsi_tree, offset, isreq,
                                        FALSE);
                break;

            case SCSI_SPC2_TESTUNITRDY:
                dissect_scsi_testunitrdy (tvb, pinfo, scsi_tree, offset,
                                          isreq, FALSE);
                break;

            default:
                call_dissector (data_handle, tvb, pinfo, scsi_tree);
                break;
            }
        }
        else if (cmd == SCSI_CMND_SBC2) {
            switch (opcode) {

            case SCSI_SBC2_FORMATUNIT:
                dissect_scsi_formatunit (tvb, pinfo, scsi_tree, offset, isreq,
                                         FALSE);
                break;

            case SCSI_SBC2_READ6:
                dissect_scsi_rdwr6 (tvb, pinfo, scsi_tree, offset, isreq,
                                    FALSE);
                break;

            case SCSI_SBC2_READ10:
                dissect_scsi_rdwr10 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            case SCSI_SBC2_READ12:
                dissect_scsi_rdwr12 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            case SCSI_SBC2_READ16:
                dissect_scsi_rdwr16 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            case SCSI_SBC2_READCAPACITY:
                dissect_scsi_readcapacity (tvb, pinfo, scsi_tree, offset,
                                           isreq, FALSE);
                break;

            case SCSI_SBC2_READDEFDATA10:
                dissect_scsi_readdefdata10 (tvb, pinfo, scsi_tree, offset,
                                            isreq, FALSE);
                break;

            case SCSI_SBC2_READDEFDATA12:
                dissect_scsi_readdefdata12 (tvb, pinfo, scsi_tree, offset,
                                            isreq, FALSE);
                break;

            case SCSI_SBC2_REASSIGNBLKS:
                dissect_scsi_reassignblks (tvb, pinfo, scsi_tree, offset,
                                           isreq, FALSE);
                break;

            case SCSI_SBC2_WRITE6:
                dissect_scsi_rdwr6 (tvb, pinfo, scsi_tree, offset, isreq,
                                    FALSE);
                break;

            case SCSI_SBC2_WRITE10:
                dissect_scsi_rdwr10 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            case SCSI_SBC2_WRITE12:
                dissect_scsi_rdwr12 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            case SCSI_SBC2_WRITE16:
                dissect_scsi_rdwr16 (tvb, pinfo, scsi_tree, offset, isreq,
                                     FALSE);
                break;

            default:
                call_dissector (data_handle, tvb, pinfo, scsi_tree);
                break;
            }
        }
        else {
            call_dissector (data_handle, tvb, pinfo, scsi_tree);
        }
    }
}

void
proto_register_scsi (void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_scsi_spcopcode,
          {"SPC-2 Opcode", "scsi.spc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_spc2_val), 0x0, "", HFILL}},
        { &hf_scsi_sbcopcode,
          {"SBC-2 Opcode", "scsi.sbc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc2_val), 0x0, "", HFILL}},
        { &hf_scsi_sscopcode,
          {"SSC-2 Opcode", "scsi.ssc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_ssc2_val), 0x0, "", HFILL}},
        { &hf_scsi_control,
          {"Control", "scsi.cdb.control", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_inquiry_flags,
          {"Flags", "scsi.inquiry.flags", FT_UINT8, BASE_BIN, NULL, 0x0, "",
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
          {"Flags", "scsi.logsel.flags", FT_UINT8, BASE_BIN, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_log_pc,
          {"Page Control", "scsi.log.pc", FT_UINT8, BASE_BIN,
           VALS (scsi_logsel_pc_val), 0xC0, "", HFILL}},
        { &hf_scsi_paramlen,
          {"Parameter Length", "scsi.cdb.paramlen", FT_UINT8, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_logsns_flags,
          {"Flags", "scsi.logsns.flags", FT_UINT16, BASE_BIN, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_logsns_pagecode,
          {"Page Code", "scsi.logsns.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_logsns_page_val), 0x3F0, "", HFILL}},
        { &hf_scsi_paramlen16,
          {"Parameter Length", "scsi.cdb.paramlen16", FT_UINT16, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_modesel_flags,
          {"Mode Sense/Select Flags", "scsi.cdb.mode.flags", FT_UINT8, BASE_BIN,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_alloclen16,
          {"Allocation Length", "scsi.cdb.alloclen16", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_modesns_pc,
          {"Page Control", "scsi.mode.pc", FT_UINT8, BASE_BIN,
           VALS (scsi_modesns_pc_val), 0xC0, "", HFILL}},
        { &hf_scsi_modesns_pagecode,
          {"Page Code", "scsi.mode.pagecode", FT_UINT8, BASE_HEX,
           VALS (scsi_modesns_page_val), 0x3F, "", HFILL}},
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
          {"Release Flags", "scsi.release.flags", FT_UINT8, BASE_BIN, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_release_thirdpartyid,
          {"Third-Party ID", "scsi.release.thirdpartyid", FT_BYTES, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_alloclen32,
          {"Allocation Length", "scsi.cdb.alloclen32", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_formatunit_flags,
          {"Flags", "scsi.formatunit.flags", FT_UINT8, BASE_BIN, NULL, 0xF8,
           "", HFILL}},
        { &hf_scsi_cdb_defectfmt,
          {"Defect List Format", "scsi.cdb.defectfmt", FT_UINT8, BASE_BIN,
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
          {"Transfer Length", "scsi.rdwr6.xferlen", FT_UINT8, BASE_DEC, NULL, 0x0,
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
          {"Flags", "scsi.readcapacity.flags", FT_UINT8, BASE_BIN, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_readcapacity_lba,
          {"Logical Block Address", "scsi.readcapacity.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_readcapacity_pmi,
          {"PMI", "scsi.readcapacity.pmi", FT_UINT8, BASE_BIN, NULL, 0x1, "",
           HFILL}},
        { &hf_scsi_readdefdata_flags,
          {"Flags", "scsi.readdefdata.flags", FT_UINT8, BASE_BIN, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_reassignblks_flags,
          {"Flags", "scsi.reassignblks.flags", FT_UINT8, BASE_BIN, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_inq_devtype,
          {"Device Type", "scsi.inquiry.devtype", FT_UINT8, BASE_HEX,
           VALS (scsi_devtype_val), 0x0F, "", HFILL}},
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
          {"Task Set Type", "scsi.mode.tst", FT_UINT8, BASE_BIN,
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scsi,
        &ett_scsi_page,
    };
    module_t *scsi_module;
    
    /* Register the protocol name and description */
    proto_scsi = proto_register_protocol("SCSI", "SCSI", "scsi");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine (&scsi_init_protocol);
    register_dissector ("SCSI", dissect_scsi, proto_scsi);
    data_handle = find_dissector ("data");

    /* add preferences to decode SCSI message */
    scsi_module = prefs_register_protocol (proto_scsi, NULL);
    prefs_register_enum_preference (scsi_module, "decode_scsi_messages_as",
                                    "Decode SCSI Messages As",
                                    "When Target Cannot Be Identified, Decode SCSI Messages As",
                                    &scsi_def_devtype, scsi_devtype_options, TRUE);
}
