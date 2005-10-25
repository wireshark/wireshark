/* packet-fc-sb3.c
 * Routines for Fibre Channel Single Byte Protocol (SBCCS); used in FICON.
 * This decoder is for FC-SB3 version 1.4
 * Copyright 2003, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include "packet-fc.h"
#include "packet-fcsb3.h"

/* Initialize the protocol and registered fields */
static int proto_fc_sbccs             = -1;
static int hf_sbccs_chid              = -1;
static int hf_sbccs_cuid              = -1;
static int hf_sbccs_devaddr           = -1;
static int hf_sbccs_ccw               = -1;
static int hf_sbccs_token             = -1;
static int hf_sbccs_dib_iucnt         = -1;
static int hf_sbccs_dib_datacnt       = -1;
static int hf_sbccs_dib_ccw_cmd       = -1;
static int hf_sbccs_dib_ccw_cnt       = -1;
static int hf_sbccs_dib_residualcnt   = -1;
static int hf_sbccs_dib_qtuf          = -1;
static int hf_sbccs_dib_qtu           = -1;
static int hf_sbccs_dib_dtuf          = -1;
static int hf_sbccs_dib_dtu           = -1;
static int hf_sbccs_dib_ctlfn         = -1;
static int hf_sbccs_lrc               = -1;
static int hf_sbccs_dib_iupacing      = -1;
static int hf_sbccs_dev_xcp_code      = -1;
static int hf_sbccs_prg_pth_errcode   = -1;
static int hf_sbccs_prg_rsp_errcode   = -1;
static int hf_sbccs_dib_ctccntr       = -1;
static int hf_sbccs_dib_lprcode       = -1;
static int hf_sbccs_dib_tin_imgid_cnt = -1;
static int hf_sbccs_dib_lrjcode       = -1;
static int hf_sbccs_dib_ioprio        = -1;
static int hf_sbccs_dib_linkctlfn     = -1;
static int hf_sbccs_iui = -1;
static int hf_sbccs_iui_as = -1;
static int hf_sbccs_iui_es = -1;
static int hf_sbccs_iui_val = -1;
static int hf_sbccs_dhflags = -1;
static int hf_sbccs_dhflags_end = -1;
static int hf_sbccs_dhflags_chaining = -1;
static int hf_sbccs_dhflags_earlyend = -1;
static int hf_sbccs_dhflags_nocrc = -1;
static int hf_sbccs_dib_ccw_flags = -1;
static int hf_sbccs_dib_ccw_flags_cd = -1;
static int hf_sbccs_dib_ccw_flags_cc = -1;
static int hf_sbccs_dib_ccw_flags_sli = -1;
static int hf_sbccs_dib_ccw_flags_crr = -1;
static int hf_sbccs_dib_cmdflags = -1;
static int hf_sbccs_dib_cmdflags_du = -1;
static int hf_sbccs_dib_cmdflags_coc = -1;
static int hf_sbccs_dib_cmdflags_syr = -1;
static int hf_sbccs_dib_cmdflags_rex = -1;
static int hf_sbccs_dib_cmdflags_sss = -1;
static int hf_sbccs_dib_statusflags = -1;
static int hf_sbccs_dib_statusflags_ffc = -1;
static int hf_sbccs_dib_statusflags_ci = -1;
static int hf_sbccs_dib_statusflags_cr = -1;
static int hf_sbccs_dib_statusflags_lri = -1;
static int hf_sbccs_dib_statusflags_rv = -1;
static int hf_sbccs_dib_status = -1;
static int hf_sbccs_dib_status_attention = -1;
static int hf_sbccs_dib_status_modifier = -1;
static int hf_sbccs_dib_status_cue = -1;
static int hf_sbccs_dib_status_busy = -1;
static int hf_sbccs_dib_status_channelend = -1;
static int hf_sbccs_dib_status_deviceend = -1;
static int hf_sbccs_dib_status_unit_check = -1;
static int hf_sbccs_dib_status_unit_exception = -1;
static int hf_sbccs_dib_ctlparam = -1;
static int hf_sbccs_dib_ctlparam_rc = -1;
static int hf_sbccs_dib_ctlparam_ru = -1;
static int hf_sbccs_dib_ctlparam_ro = -1;
static int hf_sbccs_dib_linkctlinfo = -1;
static int hf_sbccs_dib_linkctlinfo_ctcconn = -1;
static int hf_sbccs_dib_linkctlinfo_ecrcg = -1;

/* Initialize the subtree pointers */
static gint ett_fc_sbccs = -1;
static gint ett_sbccs_iui = -1;
static gint ett_sbccs_dhflags = -1;
static gint ett_sbccs_dib_ccw_flags = -1;
static gint ett_sbccs_dib_cmdflags = -1;
static gint ett_sbccs_dib_statusflags = -1;
static gint ett_sbccs_dib_status = -1;
static gint ett_sbccs_dib_ctlparam = -1;
static gint ett_sbccs_dib_linkctlinfo = -1;

static dissector_handle_t data_handle;

typedef struct {
    guint32 conv_id;
    guint32 task_id;
} sb3_task_id_t;

static const value_string fc_sbccs_iu_val[] = {
    {FC_SBCCS_IU_DATA,            "Data"},
    {FC_SBCCS_IU_CMD_HDR,         "Command Header"},
    {FC_SBCCS_IU_STATUS,          "Status"},
    {FC_SBCCS_IU_CTL,             "Control"},
    {FC_SBCCS_IU_CMD_DATA,        "Command Header & Data"},
    {FC_SBCCS_IU_CMD_LINK_CTL,    "Link Control"},
    {0x6,                         "Reserved"},
    {0x7,                         "Reserved"},
    {0x0,                         NULL},
};

static const value_string fc_sbccs_dib_cmd_val[] = {
    {0,  "Reserved"},
    {1,  "Write"},
    {2,  "Read"},
    {3,  "Control"},
    {4,  "Sense"},
    {5,  "Write (Modifier)"},
    {6,  "Read (Modifier)"},
    {7,  "Control (Modifier)"},
    {8,  "Reserved"},
    {9,  "Write (Modifier)"},
    {10, "Read (Modifier)"},
    {11, "Control (Modifier)"},
    {12, "Read Backward"},
    {13, "Write (Modifier)"},
    {14, "Read (Modifier)"},
    {15, "Control (Modifier)"},
    {0, NULL},
};

static const value_string fc_sbccs_dib_ctl_fn_val[] = {
    {FC_SBCCS_CTL_FN_CTL_END,   "Control End"},
    {FC_SBCCS_CTL_FN_CMD_RSP,   "Command Response"},
    {FC_SBCCS_CTL_FN_STK_STS,   "Stack Status"},
    {FC_SBCCS_CTL_FN_CANCEL,    "Cancel"},
    {FC_SBCCS_CTL_FN_SYS_RST,   "System Reset"},
    {FC_SBCCS_CTL_FN_SEL_RST,   "Selective Reset"},
    {FC_SBCCS_CTL_FN_REQ_STS,   "Request Status"},
    {FC_SBCCS_CTL_FN_DEV_XCP,   "Device Level Exception"},
    {FC_SBCCS_CTL_FN_STS_ACC,   "Status Accepted"},
    {FC_SBCCS_CTL_FN_DEV_ACK,   "Device-Level Ack"},
    {FC_SBCCS_CTL_FN_PRG_PTH,   "Purge Path"},
    {FC_SBCCS_CTL_FN_PRG_RSP,   "Purge Path Response"},
    {0, NULL},
};

static const value_string fc_sbccs_dib_dev_xcpcode_val[] = {
    {1, "Address Exception"},
    {0, NULL},
};

static const value_string fc_sbccs_dib_purge_path_err_val[] = {
    {0, "Error Code Xfer Not Supported"},
    {1, "SB-3 Protocol Timeout"},
    {2, "SB-3 Link Failure"},
    {3, "Reserved"},
    {4, "SB-3 Offline Condition"},
    {5, "FC-PH Link Failure"},
    {6, "SB-3 Length Error"},
    {7, "LRC Error"},
    {8, "SB-3 CRC Error"},
    {9, "IU Count Error"},
    {10, "SB-3 Link Level Protocol Error"},
    {11, "SB-3 Device Level Protocol Error"},
    {12, "Receive ABTS"},
    {13, "Cancel Function Timeout"},
    {14, "Abnormal Termination of Xchg"},
    {15, "Reserved"},
    {0,  NULL},
};

static const value_string fc_sbccs_dib_purge_path_rsp_err_val[] = {
    {0, "No Errors"},
    {1, "SB-3 Protocol Timeout"},
    {2, "SB-3 Link Failure"},
    {3, "Logical Path Timeout Error"},
    {4, "SB-3 Offline Condition"},
    {5, "FC-PH Link Failure"},
    {6, "SB-3 Length Error"},
    {7, "LRC Error"},
    {8, "SB-3 CRC Error"},
    {9, "IU Count Error"},
    {10, "SB-3 Link Level Protocol Error"},
    {11, "SB-3 Device Level Protocol Error"},
    {12, "Receive ABTS"},
    {13, "Reserved"},
    {14, "Abnormal Termination of Xchg"},
    {15, "Logical Path Not Estd"},
    {16, "Test Init Result Error"},
    {0,  NULL},
};

static const value_string fc_sbccs_dib_link_ctl_fn_val[] = {
    {FC_SBCCS_LINK_CTL_FN_ELP, "ELP"},
    {FC_SBCCS_LINK_CTL_FN_RLP, "RLP"},
    {FC_SBCCS_LINK_CTL_FN_TIN, "TIN"},
    {FC_SBCCS_LINK_CTL_FN_LPE, "LPE"},
    {FC_SBCCS_LINK_CTL_FN_LPR, "LPR"},
    {FC_SBCCS_LINK_CTL_FN_TIR, "TIR"},
    {FC_SBCCS_LINK_CTL_FN_LRJ, "LRJ"},
    {FC_SBCCS_LINK_CTL_FN_LBY, "LBY"},
    {FC_SBCCS_LINK_CTL_FN_LACK, "LACK"},
    {0, NULL},
};

static const value_string fc_sbccs_dib_lpr_errcode_val[] = {
    {0x0, "Response to RLP"},
    {0x1, "Optional Features Conflict"},
    {0x2, "Out of Resources"},
    {0x3, "Device Init In Progress"},
    {0x4, "No CU Image"},
    {0x0, NULL},
};

static const value_string fc_sbccs_dib_lrj_errcode_val[] = {
    {0x6, "Logical Path Not Estd"},
    {0x9, "Protocol Error"},
    {0x0, NULL},
};

static const true_false_string tfs_sbccs_iui_as = {
	"AS is set",
	"as is NOT set"
};
static const true_false_string tfs_sbccs_iui_es = {
	"ES is set",
	"es is NOT set"
};

static void
dissect_iui_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_iui, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_iui);
	}

	proto_tree_add_boolean(tree, hf_sbccs_iui_as, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  AS");
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_iui_es, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  ES");
	}
	flags&=(~( 0x08 ));

        proto_tree_add_item (tree, hf_sbccs_iui_val, tvb, offset, 1, 0);
	proto_item_append_text(item, val_to_str (flags & 0x7, fc_sbccs_iu_val, "0x%x"));
	flags&=(~( 0x07 ));
}

static const true_false_string tfs_sbccs_linkctlinfo_ctcconn = {
	"CTC Conn supported",
	"Ctc conn NOT supported"
};
static const true_false_string tfs_sbccs_linkctlinfo_ecrcg = {
	"Enhanced CRC Generation supported",
	"Enhanced crc generation NOT supported"
};

static void
dissect_linkctlinfo (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_linkctlinfo, 
				tvb, offset, 2, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_linkctlinfo);
	}

	proto_tree_add_boolean(tree, hf_sbccs_dib_linkctlinfo_ctcconn, tvb, offset, 2, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  CTC Conn");
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_linkctlinfo_ecrcg, tvb, offset, 2, flags);
	if (flags&0x01){
		proto_item_append_text(item, "  Enhanced CRC Gen");
	}
	flags&=(~( 0x01 ));
}


static const true_false_string tfs_sbccs_dhflags_end = {
	"END bit is set",
	"end bit is NOT set"
};
static const true_false_string tfs_sbccs_dhflags_chaining = {
	"CHAINING bit is set",
	"chaining bit is NOT set"
};
static const true_false_string tfs_sbccs_dhflags_earlyend = {
	"EARLYEND bit is set",
	"earlyend bit is NOT set"
};
static const true_false_string tfs_sbccs_dhflags_nocrc = {
	"NOCRC bit is set",
	"nocrc bit is NOT set"
};

static void
dissect_dh_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dhflags, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dhflags);
	}

	proto_tree_add_boolean(tree, hf_sbccs_dhflags_end, tvb, offset, 1, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  End");
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_sbccs_dhflags_chaining, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  Chaining");
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_dhflags_earlyend, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  Early End");
	}
	flags&=(~( 0x08 ));

	proto_tree_add_boolean(tree, hf_sbccs_dhflags_nocrc, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, "  No CRC");
	}
	flags&=(~( 0x04 ));
}

static const true_false_string tfs_sbccs_ccwflags_cd = {
	"CD is set",
	"cd is NOT set"
};
static const true_false_string tfs_sbccs_ccwflags_cc = {
	"CC is set",
	"cc is NOT set"
};
static const true_false_string tfs_sbccs_ccwflags_sli = {
	"SLI is set",
	"sli is NOT set"
};
static const true_false_string tfs_sbccs_ccwflags_crr = {
	"CRR is set",
	"crr is NOT set"
};

static void
dissect_ccw_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_ccw_flags, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_ccw_flags);
	}

	proto_tree_add_boolean(tree, hf_sbccs_dib_ccw_flags_cd, tvb, offset, 1, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  CD");
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_ccw_flags_cc, tvb, offset, 1, flags);
	if (flags&0x40){
		proto_item_append_text(item, "  CC");
	}
	flags&=(~( 0x40 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_ccw_flags_sli, tvb, offset, 1, flags);
	if (flags&0x20){
		proto_item_append_text(item, "  SLI");
	}
	flags&=(~( 0x20 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_ccw_flags_crr, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  CRR");
	}
	flags&=(~( 0x08 ));
}

static const true_false_string tfs_sbccs_cmdflags_du = {
	"DU is set",
	"du is NOT set"
};
static const true_false_string tfs_sbccs_cmdflags_coc = {
	"COC is set",
	"coc is NOT set"
};
static const true_false_string tfs_sbccs_cmdflags_syr = {
	"SYR is set",
	"syr is NOT set"
};
static const true_false_string tfs_sbccs_cmdflags_rex = {
	"REX is set",
	"rex is NOT set"
};
static const true_false_string tfs_sbccs_cmdflags_sss = {
	"SSS is set",
	"sss is NOT set"
};

static void
dissect_cmd_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_cmdflags, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_cmdflags);
	}

	proto_tree_add_boolean(tree, hf_sbccs_dib_cmdflags_du, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  DU");
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_cmdflags_coc, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  COC");
	}
	flags&=(~( 0x08 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_cmdflags_syr, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, "  SYR");
	}
	flags&=(~( 0x04 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_cmdflags_rex, tvb, offset, 1, flags);
	if (flags&0x02){
		proto_item_append_text(item, "  REX");
	}
	flags&=(~( 0x02 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_cmdflags_sss, tvb, offset, 1, flags);
	if (flags&0x01){
		proto_item_append_text(item, "  SSS");
	}
	flags&=(~( 0x01 ));
}

static const value_string status_ffc_val[] = {
	{ 0, "" },
	{ 1, "FFC:Queuing Information Valid" },
	{ 2, "FFC:Resetting Event" },
	{ 0, NULL }
};

static const true_false_string tfs_sbccs_statusflags_ci = {
	"CI is set",
	"ci is NOT set"
};
static const true_false_string tfs_sbccs_statusflags_cr = {
	"CR is set",
	"cr is NOT set"
};
static const true_false_string tfs_sbccs_statusflags_lri = {
	"LRI is set",
	"lri is NOT set"
};
static const true_false_string tfs_sbccs_statusflags_rv = {
	"RV is set",
	"rv is NOT set"
};

static void
dissect_status_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_statusflags, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_statusflags);
	}


        proto_tree_add_item (tree, hf_sbccs_dib_statusflags_ffc, tvb, offset, 1, 0);
	proto_item_append_text(item, val_to_str ((flags>>5)&0x07, status_ffc_val, "Reserved:0x%x"));
	flags&=(~( 0xE0 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_statusflags_ci, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  CI");
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_statusflags_cr, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, "  CR");
	}
	flags&=(~( 0x04 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_statusflags_lri, tvb, offset, 1, flags);
	if (flags&0x02){
		proto_item_append_text(item, "  LRI");
	}
	flags&=(~( 0x02 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_statusflags_rv, tvb, offset, 1, flags);
	if (flags&0x01){
		proto_item_append_text(item, "  RV");
	}
	flags&=(~( 0x01 ));

}

static const true_false_string tfs_sbccs_status_attention = {
	"ATTENTION is set",
	"attention is NOT set"
};
static const true_false_string tfs_sbccs_status_modifier = {
	"STATUS MODIFIER is set",
	"status modifier is NOT set"
};
static const true_false_string tfs_sbccs_status_cue = {
	"CONTROL-UNIT END is set",
	"control-unit end is NOT set"
};
static const true_false_string tfs_sbccs_status_busy = {
	"BUSY is set",
	"busy is NOT set"
};
static const true_false_string tfs_sbccs_status_channelend = {
	"CHANNEL-END is set",
	"channel-end is NOT set"
};
static const true_false_string tfs_sbccs_status_deviceend = {
	"DEVICE-END is set",
	"device-end is NOT set"
};
static const true_false_string tfs_sbccs_status_unitcheck = {
	"UNIT CHECK is set",
	"unit check is NOT set"
};
static const true_false_string tfs_sbccs_status_unitexception = {
	"UNIT EXCEPTION is set",
	"unit exception is NOT set"
};

static void
dissect_status (packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_status, 
				tvb, offset, 1, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_status);
	}


	proto_tree_add_boolean(tree, hf_sbccs_dib_status_attention, tvb, offset, 1, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  Attention");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Attention");
		}
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_modifier, tvb, offset, 1, flags);
	if (flags&0x40){
		proto_item_append_text(item, "  Status Modifier");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Status Modifier");
		}
	}
	flags&=(~( 0x40 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_cue, tvb, offset, 1, flags);
	if (flags&0x20){
		proto_item_append_text(item, "  Control-Unit End");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Control-Unit End");
		}
	}
	flags&=(~( 0x20 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_busy, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  Busy");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Busy");
		}
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_channelend, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  Channel End");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Channel End");
		}
	}
	flags&=(~( 0x08 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_deviceend, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, "  Device End");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Device End");
		}
	}
	flags&=(~( 0x04 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_unit_check, tvb, offset, 1, flags);
	if (flags&0x02){
		proto_item_append_text(item, "  Unit Check");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Unit Check");
		}
	}
	flags&=(~( 0x02 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_status_unit_exception, tvb, offset, 1, flags);
	if (flags&0x01){
		proto_item_append_text(item, "  Unit Exception");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, "  Unit Exception");
		}
	}
	flags&=(~( 0x01 ));

}

static const true_false_string tfs_sbccs_ctlparam_rc = {
	"RC is SET",
	"rc is NOT set"
};
static const true_false_string tfs_sbccs_ctlparam_ru = {
	"RU is SET",
	"ru is NOT set"
};
static const true_false_string tfs_sbccs_ctlparam_ro = {
	"RO is SET",
	"ro is NOT set"
};

static void
dissect_sel_rst_param (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint32 flags)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
    
	if(parent_tree){
		item=proto_tree_add_uint(parent_tree, hf_sbccs_dib_ctlparam, 
				tvb, offset, 3, flags);
		tree=proto_item_add_subtree(item, ett_sbccs_dib_ctlparam);
	}

	proto_tree_add_boolean(tree, hf_sbccs_dib_ctlparam_rc, tvb, offset, 3, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  RC");
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_ctlparam_ru, tvb, offset, 3, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  RU");
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_sbccs_dib_ctlparam_ro, tvb, offset, 3, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  RO");
	}
	flags&=(~( 0x08 ));
}

static void get_fc_sbccs_conv_data (tvbuff_t *tvb, guint offset,
                                    guint16 *ch_cu_id, guint16 *dev_addr,
                                    guint16 *ccw)
{
    *ch_cu_id = *dev_addr = *ccw = 0;

    *ch_cu_id = (tvb_get_guint8 (tvb, offset+1)) << 8;
    *ch_cu_id |= tvb_get_guint8 (tvb, offset+3);
    *dev_addr = tvb_get_ntohs (tvb, offset+4);
    *ccw = tvb_get_ntohs (tvb, offset+10);
}

/* Decode both the SB-3 and basic IU header */
static void
dissect_fc_sbccs_sb3_iu_hdr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset)
{
    proto_item *subti;
    proto_tree *sb3hdr_tree;
    proto_tree *iuhdr_tree;
    guint8 iui, dhflags;
    guint type;
    
    /* Decode the basic SB3 and IU header and determine type of frame */
    type = get_fc_sbccs_iu_type (tvb, offset);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_set_str (pinfo->cinfo, COL_INFO, val_to_str (type, fc_sbccs_iu_val,
                                                         "0x%x"));
    }
    
    if (tree) {
        /* Dissect SB3 header first */
        subti = proto_tree_add_text (tree, tvb, offset, FC_SBCCS_SB3_HDR_SIZE,
                                     "SB-3 Header");
        sb3hdr_tree = proto_item_add_subtree (subti, ett_fc_sbccs);

        proto_tree_add_item (sb3hdr_tree, hf_sbccs_chid, tvb, offset+1, 1, 0);
        proto_tree_add_item (sb3hdr_tree, hf_sbccs_cuid, tvb, offset+3, 1, 0);
        proto_tree_add_item (sb3hdr_tree, hf_sbccs_devaddr, tvb, offset+4, 2, 0);

        /* Dissect IU Header */
        subti = proto_tree_add_text (tree, tvb, offset + FC_SBCCS_SB3_HDR_SIZE,
                                     FC_SBCCS_IU_HDR_SIZE, "IU Header");
        iuhdr_tree = proto_item_add_subtree (subti, ett_fc_sbccs);
        offset += FC_SBCCS_SB3_HDR_SIZE;

        iui = tvb_get_guint8 (tvb, offset);
	dissect_iui_flags(iuhdr_tree, tvb, offset, iui);

        dhflags = tvb_get_guint8 (tvb, offset+1);
	dissect_dh_flags(iuhdr_tree, tvb, offset+1, dhflags);
        
        proto_tree_add_item (iuhdr_tree, hf_sbccs_ccw, tvb, offset+2, 2, 0);
        proto_tree_add_item (iuhdr_tree, hf_sbccs_token, tvb, offset+5, 3, 0);
    }
}

static void dissect_fc_sbccs_dib_data_hdr (tvbuff_t *tvb,
                                           packet_info *pinfo _U_,
                                           proto_tree *tree, guint offset)
{
    if (tree) {
        proto_tree_add_item (tree, hf_sbccs_dib_iucnt, tvb, offset+9, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_datacnt, tvb, offset+10, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_lrc, tvb, offset+12, 4, 0);
    }
}

static void dissect_fc_sbccs_dib_cmd_hdr (tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree, guint offset)
{
    guint8 flags;

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_append_fstr (pinfo->cinfo, COL_INFO,
                         ": %s", val_to_str (tvb_get_guint8 (tvb, offset),
                                             fc_sbccs_dib_cmd_val,
                                             "0x%x"));
    }
    
    if (tree) {
        proto_tree_add_item (tree, hf_sbccs_dib_ccw_cmd, tvb, offset, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+1);
	dissect_ccw_flags(tree, tvb, offset+1, flags);

        proto_tree_add_item (tree, hf_sbccs_dib_ccw_cnt, tvb, offset+2, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_ioprio, tvb, offset+5, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+7);
	dissect_cmd_flags(tree, tvb, offset+7, flags);

        proto_tree_add_item (tree, hf_sbccs_dib_iucnt, tvb, offset+9, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_datacnt, tvb, offset+10, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_lrc, tvb, offset+12, 4, 0);

    }
}

static void dissect_fc_sbccs_dib_status_hdr (tvbuff_t *tvb, packet_info *pinfo,
                                             proto_tree *tree, guint offset)
{
    guint8 flags;
    gboolean rv_valid, qparam_valid;
    tvbuff_t *next_tvb;
    guint16 supp_status_cnt = 0;

    if (tree) {
        flags = tvb_get_guint8 (tvb, offset);
        rv_valid = flags & 0x1; /* if residual count is valid */
        qparam_valid = (((flags & 0xE0) >> 5) == 0x1); /* From the FFC field */
	dissect_status_flags(tree, tvb, offset, flags);
        
        flags = tvb_get_guint8 (tvb, offset+1);
	dissect_status(pinfo, tree, tvb, offset+1, flags);

        if (rv_valid) {
            proto_tree_add_item (tree, hf_sbccs_dib_residualcnt, tvb, offset+2,
                                 2, 0);
        }
        else {
            proto_tree_add_item (tree, hf_sbccs_dib_iupacing, tvb, offset+3,
                                 1, 0);
        }
        
        if (qparam_valid) {
            proto_tree_add_item (tree, hf_sbccs_dib_qtuf, tvb, offset+4, 1, 0);
            proto_tree_add_item (tree, hf_sbccs_dib_qtu, tvb, offset+4, 2, 0);
        }

        proto_tree_add_item (tree, hf_sbccs_dib_dtuf, tvb, offset+6, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_dtu, tvb, offset+6, 2, 0);

        proto_tree_add_item (tree, hf_sbccs_dib_iucnt, tvb, offset+9, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_datacnt, tvb, offset+10, 2, 0);
        supp_status_cnt = tvb_get_ntohs (tvb, offset+10);
        proto_tree_add_item (tree, hf_sbccs_lrc, tvb, offset+12, 4, 0);

        if (supp_status_cnt) {
            next_tvb = tvb_new_subset (tvb, offset+FC_SBCCS_DIB_LRC_HDR_SIZE,
                                       -1, -1);
            call_dissector (data_handle, next_tvb, pinfo, tree);
        }
    }
}

static void dissect_fc_sbccs_dib_ctl_hdr (tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree, guint offset)
{
    guint8 ctlfn;

    ctlfn = tvb_get_guint8 (tvb, offset);
    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_append_fstr (pinfo->cinfo, COL_INFO,
                         ": %s",
                         val_to_str (ctlfn, 
                                     fc_sbccs_dib_ctl_fn_val,
                                     "0x%x"));
    }
    if (tree) {
        proto_tree_add_item (tree, hf_sbccs_dib_ctlfn, tvb, offset, 1, 0);

        /* Control Function Parameter is to be interpreted in some cases */
        switch (ctlfn) {
        case FC_SBCCS_CTL_FN_SEL_RST:
            dissect_sel_rst_param(tree, tvb, offset+1, tvb_get_ntoh24 (tvb, offset+1));
            break;
        case FC_SBCCS_CTL_FN_DEV_XCP:
            proto_tree_add_item (tree, hf_sbccs_dev_xcp_code, tvb, offset+1,
                                 1, 0);
            break;
        case FC_SBCCS_CTL_FN_PRG_PTH:
            proto_tree_add_item (tree, hf_sbccs_prg_pth_errcode, tvb, offset+1,
                                 1, 0);
            break;
        default:
            proto_tree_add_item (tree, hf_sbccs_dib_ctlparam, tvb, offset+1,
                                 3, 0);
            break;
        }
        
        proto_tree_add_item (tree, hf_sbccs_dib_iucnt, tvb, offset+9, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_datacnt, tvb, offset+10, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_lrc, tvb, offset+12, 4, 0);

        if (ctlfn == FC_SBCCS_CTL_FN_PRG_RSP) {
            /* Need to decode the LESBs */
            proto_tree_add_item (tree, hf_sbccs_prg_rsp_errcode, tvb, offset+60,
                                 1, 0);
        }
    }
}

static void dissect_fc_sbccs_dib_link_hdr (tvbuff_t *tvb, packet_info *pinfo,
                                           proto_tree *tree, guint offset)
{
    guint8 link_ctl;
    guint16 ctl_info;
    guint link_payload_len, i;

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_append_fstr (pinfo->cinfo, COL_INFO,
                         ": %s",
                         val_to_str (tvb_get_guint8 (tvb, offset+1),
                                     fc_sbccs_dib_link_ctl_fn_val,
                                     "0x%x"));
    }

    if (tree) {
        link_ctl = tvb_get_guint8 (tvb, offset+1);
        proto_tree_add_item (tree, hf_sbccs_dib_linkctlfn, tvb, offset+1, 1, 0);

        ctl_info = tvb_get_ntohs (tvb, offset+2);
        switch (link_ctl) {
        case FC_SBCCS_LINK_CTL_FN_ELP:
        case FC_SBCCS_LINK_CTL_FN_LPE:
            dissect_linkctlinfo(tree, tvb, offset+2, ctl_info);
            break;
        case FC_SBCCS_LINK_CTL_FN_LPR:
            proto_tree_add_item (tree, hf_sbccs_dib_lprcode, tvb, offset+2, 1,
                                 0);
            break;
        case FC_SBCCS_LINK_CTL_FN_TIN:
            proto_tree_add_item (tree, hf_sbccs_dib_tin_imgid_cnt, tvb,
                                 offset+3, 1, 0);
            break;
        case FC_SBCCS_LINK_CTL_FN_TIR:
            proto_tree_add_item (tree, hf_sbccs_dib_tin_imgid_cnt, tvb,
                                 offset+3, 1, 0);
            break;
        case FC_SBCCS_LINK_CTL_FN_LRJ:
            proto_tree_add_item (tree, hf_sbccs_dib_lrjcode, tvb, offset+2,
                                 1, 0);
            break;
        default:
            /* Do Nothing */
            break;
        }

        proto_tree_add_item (tree, hf_sbccs_dib_ctccntr, tvb, offset+4, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_iucnt, tvb, offset+9, 1, 0);
        proto_tree_add_item (tree, hf_sbccs_dib_datacnt, tvb, offset+10, 2, 0);
        proto_tree_add_item (tree, hf_sbccs_lrc, tvb, offset+12, 4, 0);

        if (link_ctl == FC_SBCCS_LINK_CTL_FN_TIR) {
            link_payload_len = tvb_get_ntohs (tvb, offset+10);
            i = 0;
            offset += 16;
            
            while (i < link_payload_len) {
                proto_tree_add_text (tree, tvb, offset, 4,
                                     "Logical Paths %d-%d: %s",
                                     i*8, ((i+4)*8) - 1,
                                     tvb_bytes_to_str_punct (tvb, offset, 4, ':'));
                i += 4;
                offset += 4;
            }
        }
    }
}

static void dissect_fc_sbccs (tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree)
{
    guint8 type;
    guint16 ch_cu_id, dev_addr, ccw;
    guint offset = 0; 
    proto_item *ti;
    proto_tree *sb3_tree = NULL,
               *dib_tree = NULL;
    tvbuff_t *next_tvb;
    conversation_t *conversation;
    sb3_task_id_t task_key;
        
    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC-SB3");

    /* Decode the basic SB3 and IU header and determine type of frame */
    type = get_fc_sbccs_iu_type (tvb, offset);
    get_fc_sbccs_conv_data (tvb, offset, &ch_cu_id, &dev_addr, &ccw);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_set_str (pinfo->cinfo, COL_INFO, val_to_str (type, fc_sbccs_iu_val,
                                                         "0x%x"));
    }
    
    /* Retrieve conversation state to determine expected payload */
    conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                      PT_SBCCS, ch_cu_id, dev_addr, 0);
                                      
    if (conversation) {
        task_key.conv_id = conversation->index;
        task_key.task_id = ccw;
        pinfo->private_data = (void *)&task_key;

    }
    else if ((type == FC_SBCCS_IU_CMD_HDR) || 
             (type != FC_SBCCS_IU_CMD_DATA)) {
        conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_SBCCS, ch_cu_id, dev_addr, 0);
        task_key.conv_id = conversation->index;
        task_key.task_id = ccw;
        pinfo->private_data = (void *)&task_key;
    }
    else {
        pinfo->private_data = NULL;
    }
    
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fc_sbccs, tvb, 0, -1,
                                             "FC-SB3");
        sb3_tree = proto_item_add_subtree (ti, ett_fc_sbccs);

        dissect_fc_sbccs_sb3_iu_hdr (tvb, pinfo, sb3_tree, offset);
        offset += (FC_SBCCS_SB3_HDR_SIZE + FC_SBCCS_IU_HDR_SIZE);

        ti = proto_tree_add_text (sb3_tree, tvb, offset,
                                  FC_SBCCS_DIB_LRC_HDR_SIZE, "DIB Header");
        dib_tree = proto_item_add_subtree (ti, ett_fc_sbccs);
    }
    else {
        offset += (FC_SBCCS_SB3_HDR_SIZE + FC_SBCCS_IU_HDR_SIZE);
    }
    
    switch (type) {
    case FC_SBCCS_IU_DATA:
        dissect_fc_sbccs_dib_data_hdr (tvb, pinfo, dib_tree, offset);
        break;
    case FC_SBCCS_IU_CMD_HDR:
    case FC_SBCCS_IU_CMD_DATA:
        dissect_fc_sbccs_dib_cmd_hdr (tvb, pinfo, dib_tree, offset);
        break;
    case FC_SBCCS_IU_STATUS:
        dissect_fc_sbccs_dib_status_hdr (tvb, pinfo, dib_tree, offset);
        break;
    case FC_SBCCS_IU_CTL:
        dissect_fc_sbccs_dib_ctl_hdr (tvb, pinfo, dib_tree, offset);
        break;
    case FC_SBCCS_IU_CMD_LINK_CTL:
        dissect_fc_sbccs_dib_link_hdr (tvb, pinfo, dib_tree, offset);
        break;
    default:
        next_tvb = tvb_new_subset (tvb, offset, -1, -1);
        call_dissector (data_handle, next_tvb, pinfo, dib_tree);
        break;
    }

    if ((get_fc_sbccs_iu_type (tvb, 0) != FC_SBCCS_IU_CTL) &&
        (get_fc_sbccs_iu_type (tvb, 0) != FC_SBCCS_IU_CMD_LINK_CTL))  {
        next_tvb = tvb_new_subset (tvb, offset+FC_SBCCS_DIB_LRC_HDR_SIZE,
                                   -1, -1);
        call_dissector (data_handle, next_tvb, pinfo, tree);
    }
}

/* Register the protocol with Ethereal */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fcsbccs (void)
{                 
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_sbccs_chid,
          {"Channel Image ID", "sbccs.chid", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_cuid,
          {"Control Unit Image ID", "sbccs.cuid", FT_UINT8, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_sbccs_devaddr,
          {"Device Address", "sbccs.devaddr", FT_UINT16, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_iui,
          {"Information Unit Identifier", "sbccs.iui", FT_UINT8, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dhflags,
          {"DH Flags", "sbccs.dhflags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_sbccs_ccw,
          {"CCW Number", "sbccs.ccw", FT_UINT16, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_sbccs_token,
          {"Token", "sbccs.token", FT_UINT24, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_sbccs_dib_iucnt,
          {"DIB IU Count", "sbccs.iucnt", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_dib_datacnt,
          {"DIB Data Byte Count", "sbccs.databytecnt", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dib_ccw_cmd,
          {"CCW Command", "sbccs.ccwcmd", FT_UINT8, BASE_HEX,
           VALS (fc_sbccs_dib_cmd_val), 0x0, "", HFILL}},
        { &hf_sbccs_dib_ccw_cnt,
          {"CCW Count", "sbccs.ccwcnt", FT_UINT16, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_sbccs_dib_ioprio,
          {"I/O Priority", "sbccs.ioprio", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_dib_status,
          {"Status", "sbccs.status", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_sbccs_dib_residualcnt,
          {"Residual Count", "sbccs.residualcnt", FT_UINT8, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dib_iupacing,
          {"IU Pacing", "sbccs.iupacing", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_dib_qtuf,
          {"Queue-Time Unit Factor", "sbccs.qtuf", FT_UINT8, BASE_DEC,
           NULL, 0xF0, "", HFILL}},
        { &hf_sbccs_dib_qtu,
          {"Queue-Time Unit", "sbccs.qtu", FT_UINT16, BASE_DEC, NULL, 0xFFF,
           "", HFILL}},
        { &hf_sbccs_dib_dtuf,
          {"Defer-Time Unit Function", "sbccs.dtuf", FT_UINT8, BASE_DEC,
           NULL, 0xF0, "", HFILL}},
        { &hf_sbccs_dib_dtu,
          {"Defer-Time Unit", "sbccs.dtu", FT_UINT16, BASE_DEC, NULL, 0xFFF,
           "", HFILL}},
        { &hf_sbccs_dib_ctlfn,
          {"Control Function", "sbccs.ctlfn", FT_UINT8, BASE_HEX,
           VALS (fc_sbccs_dib_ctl_fn_val), 0x0, "", HFILL}},
        { &hf_sbccs_dib_linkctlfn,
          {"Link Control Function", "sbccs.linkctlfn", FT_UINT8, BASE_HEX,
           VALS (fc_sbccs_dib_link_ctl_fn_val), 0x0, "", HFILL}},
        { &hf_sbccs_dib_ctccntr,
          {"CTC Counter", "sbccs.ctccntr", FT_UINT16, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_lrc,
          {"LRC", "sbccs.lrc", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dev_xcp_code,
          {"Device Level Exception Code", "sbccs.dip.xcpcode", FT_UINT8,
           BASE_DEC, VALS (fc_sbccs_dib_dev_xcpcode_val), 0x0, "", HFILL}},
        { &hf_sbccs_prg_pth_errcode,
          {"Purge Path Error Code", "sbccs.purgepathcode", FT_UINT8,
           BASE_DEC, VALS (fc_sbccs_dib_purge_path_err_val), 0x0, "", HFILL}},
        { &hf_sbccs_prg_rsp_errcode,
          {"Purge Path Response Error Code", "sbccs.purgepathrspcode",
           FT_UINT8, BASE_DEC, VALS (fc_sbccs_dib_purge_path_rsp_err_val),
           0x0, "", HFILL}},
        { &hf_sbccs_dib_lprcode,
          {"LPR Reason Code", "sbccs.lprcode", FT_UINT8, BASE_DEC,
           VALS (fc_sbccs_dib_lpr_errcode_val), 0xF, "", HFILL}},
        { &hf_sbccs_dib_tin_imgid_cnt,
          {"TIN Image ID", "sbccs.tinimageidcnt", FT_UINT8, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_sbccs_dib_lrjcode,
          {"LRJ Reaspn Code", "sbccs.lrjcode", FT_UINT8, BASE_HEX,
           VALS (fc_sbccs_dib_lrj_errcode_val), 0x7F, "", HFILL}},
        { &hf_sbccs_iui_as,
          {"AS", "sbccs.iui.as", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_iui_as), 0x10, "", HFILL}},
        { &hf_sbccs_iui_es,
          {"ES", "sbccs.iui.es", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_iui_es), 0x08, "", HFILL}},
        { &hf_sbccs_iui_val,
          {"Val", "sbccs.iui.val", FT_UINT8, BASE_HEX,
           VALS(fc_sbccs_iu_val), 0x07, "", HFILL}},
        { &hf_sbccs_dhflags_end,
          {"End", "sbccs.dhflags.end", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_dhflags_end), 0x80, "", HFILL}},
        { &hf_sbccs_dhflags_chaining,
          {"Chaining", "sbccs.dhflags.chaining", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_dhflags_chaining), 0x10, "", HFILL}},
        { &hf_sbccs_dhflags_earlyend,
          {"Early End", "sbccs.dhflags.earlyend", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_dhflags_earlyend), 0x08, "", HFILL}},
        { &hf_sbccs_dhflags_nocrc,
          {"No CRC", "sbccs.dhflags.nocrc", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_dhflags_nocrc), 0x04, "", HFILL}},
        { &hf_sbccs_dib_ccw_flags,
          {"CCW Control Flags", "sbccs.ccwflags", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_sbccs_dib_ccw_flags_cd,
          {"CD", "sbccs.ccwflags.cd", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_ccwflags_cd), 0x80, "", HFILL}},
        { &hf_sbccs_dib_ccw_flags_cc,
          {"CC", "sbccs.ccwflags.cc", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_ccwflags_cc), 0x40, "", HFILL}},
        { &hf_sbccs_dib_ccw_flags_sli,
          {"SLI", "sbccs.ccwflags.sli", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_ccwflags_sli), 0x20, "", HFILL}},
        { &hf_sbccs_dib_ccw_flags_crr,
          {"CRR", "sbccs.ccwflags.crr", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_ccwflags_crr), 0x08, "", HFILL}},
        { &hf_sbccs_dib_cmdflags,
          {"Command Flags", "sbccs.cmdflags", FT_UINT8, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_sbccs_dib_cmdflags_du,
          {"DU", "sbccs.cmdflags.du", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_cmdflags_du), 0x10, "", HFILL}},
        { &hf_sbccs_dib_cmdflags_coc,
          {"COC", "sbccs.cmdflags.coc", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_cmdflags_coc), 0x08, "", HFILL}},
        { &hf_sbccs_dib_cmdflags_syr,
          {"SYR", "sbccs.cmdflags.syr", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_cmdflags_syr), 0x04, "", HFILL}},
        { &hf_sbccs_dib_cmdflags_rex,
          {"REX", "sbccs.cmdflags.rex", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_cmdflags_rex), 0x02, "", HFILL}},
        { &hf_sbccs_dib_cmdflags_sss,
          {"SSS", "sbccs.cmdflags.sss", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_cmdflags_sss), 0x01, "", HFILL}},
        { &hf_sbccs_dib_statusflags,
          {"Status Flags", "sbccs.statusflags", FT_UINT8, BASE_HEX,
           NULL, 0, "", HFILL}},
        { &hf_sbccs_dib_statusflags_ffc,
          {"FFC", "sbccs.statusflags.ffc", FT_UINT8, BASE_HEX,
           VALS(status_ffc_val), 0xE0, "", HFILL}},
        { &hf_sbccs_dib_statusflags_ci,
          {"CI", "sbccs.statusflags.ci", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_statusflags_ci), 0x10, "", HFILL}},
        { &hf_sbccs_dib_statusflags_cr,
          {"CR", "sbccs.statusflags.cr", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_statusflags_cr), 0x04, "", HFILL}},
        { &hf_sbccs_dib_statusflags_lri,
          {"LRI", "sbccs.statusflags.lri", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_statusflags_lri), 0x02, "", HFILL}},
        { &hf_sbccs_dib_statusflags_rv,
          {"RV", "sbccs.statusflags.rv", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_statusflags_rv), 0x01, "", HFILL}},
        { &hf_sbccs_dib_status_attention,
          {"Attention", "sbccs.status.attention", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_attention), 0x80, "", HFILL}},
        { &hf_sbccs_dib_status_modifier,
          {"Status Modifier", "sbccs.status.modifier", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_modifier), 0x40, "", HFILL}},
        { &hf_sbccs_dib_status_cue,
          {"Control-Unit End", "sbccs.status.cue", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_cue), 0x20, "", HFILL}},
        { &hf_sbccs_dib_status_busy,
          {"Busy", "sbccs.status.busy", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_busy), 0x10, "", HFILL}},
        { &hf_sbccs_dib_status_channelend,
          {"Channel End", "sbccs.status.channel_end", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_channelend), 0x08, "", HFILL}},
        { &hf_sbccs_dib_status_deviceend,
          {"Device End", "sbccs.status.device_end", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_deviceend), 0x04, "", HFILL}},
        { &hf_sbccs_dib_status_unit_check,
          {"Unit Check", "sbccs.status.unit_check", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_unitcheck), 0x02, "", HFILL}},
        { &hf_sbccs_dib_status_unit_exception,
          {"Unit Exception", "sbccs.status.unitexception", FT_BOOLEAN, 8,
           TFS(&tfs_sbccs_status_unitexception), 0x01, "", HFILL}},
        { &hf_sbccs_dib_ctlparam,
          {"Control Parameters", "sbccs.ctlparam", FT_UINT24, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dib_ctlparam_rc,
          {"RC", "sbccs.ctlparam.rc", FT_BOOLEAN, 24,
           TFS(&tfs_sbccs_ctlparam_rc), 0x80, "", HFILL}},
        { &hf_sbccs_dib_ctlparam_ru,
          {"RU", "sbccs.ctlparam.ru", FT_BOOLEAN, 24,
           TFS(&tfs_sbccs_ctlparam_ru), 0x10, "", HFILL}},
        { &hf_sbccs_dib_ctlparam_ro,
          {"RO", "sbccs.ctlparam.ro", FT_BOOLEAN, 24,
           TFS(&tfs_sbccs_ctlparam_ro), 0x08, "", HFILL}},
        { &hf_sbccs_dib_linkctlinfo,
          {"Link Control Information", "sbccs.linkctlinfo", FT_UINT16,
           BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_sbccs_dib_linkctlinfo_ctcconn,
          {"CTC Conn", "sbccs.linkctlinfo.ctc_conn", FT_BOOLEAN, 16,
           TFS(&tfs_sbccs_linkctlinfo_ctcconn), 0x80, "", HFILL}},
        { &hf_sbccs_dib_linkctlinfo_ecrcg,
          {"Enhanced CRC Generation", "sbccs.linkctlinfo.ecrcg", FT_BOOLEAN, 16,
           TFS(&tfs_sbccs_linkctlinfo_ecrcg), 0x01, "", HFILL}},
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fc_sbccs,
        &ett_sbccs_iui,
        &ett_sbccs_dhflags,
        &ett_sbccs_dib_ccw_flags,
        &ett_sbccs_dib_cmdflags,
        &ett_sbccs_dib_statusflags,
        &ett_sbccs_dib_status,
        &ett_sbccs_dib_ctlparam,
        &ett_sbccs_dib_linkctlinfo,
    };

    /* Register the protocol name and description */
    proto_fc_sbccs = proto_register_protocol ("Fibre Channel Single Byte Command",
                                              "FC-SB3", "sb3");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fc_sbccs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fcsbccs (void)
{
    dissector_handle_t fc_sbccs_handle;

    fc_sbccs_handle = create_dissector_handle (dissect_fc_sbccs,
                                               proto_fc_sbccs);

    dissector_add("fc.ftype", FC_FTYPE_SBCCS, fc_sbccs_handle);

    data_handle = find_dissector ("data");
}


