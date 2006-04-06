/* packet-fcp.c
 * Routines for Fibre Channel Protocol for SCSI (FCP)
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include "packet-fc.h"
#include "packet-fcp.h"
#include "packet-scsi.h"

/* Initialize the protocol and registered fields */
static int proto_fcp         = -1;
static int hf_fcp_multilun   = -1;
static int hf_fcp_singlelun  = -1;
static int hf_fcp_crn        = -1;
static int hf_fcp_taskattr   = -1;
static int hf_fcp_taskmgmt   = -1;
static int hf_fcp_addlcdblen = -1;
static int hf_fcp_rddata     = -1;
static int hf_fcp_wrdata     = -1;
static int hf_fcp_dl         = -1;
static int hf_fcp_data_ro    = -1;
static int hf_fcp_burstlen   = -1;
static int hf_fcp_rspflags   = -1;
static int hf_fcp_retry_delay_timer   = -1;
static int hf_fcp_resid      = -1;
static int hf_fcp_bidir_resid = -1;
static int hf_fcp_snslen     = -1;
static int hf_fcp_rsplen     = -1;
static int hf_fcp_rspcode    = -1;
static int hf_fcp_scsistatus = -1;
static int hf_fcp_type = -1;
static int hf_fcp_mgmt_flags_obsolete = -1;
static int hf_fcp_mgmt_flags_clear_aca = -1;
static int hf_fcp_mgmt_flags_target_reset = -1;
static int hf_fcp_mgmt_flags_lu_reset = -1;
static int hf_fcp_mgmt_flags_rsvd = -1;
static int hf_fcp_mgmt_flags_clear_task_set = -1;
static int hf_fcp_mgmt_flags_abort_task_set = -1;
static int hf_fcp_rsp_flags_bidi = -1;
static int hf_fcp_rsp_flags_bidi_rru = -1;
static int hf_fcp_rsp_flags_bidi_rro = -1;
static int hf_fcp_rsp_flags_conf_req = -1;
static int hf_fcp_rsp_flags_resid_under = -1;
static int hf_fcp_rsp_flags_resid_over = -1;
static int hf_fcp_rsp_flags_sns_vld = -1;
static int hf_fcp_rsp_flags_res_vld = -1;

/* Initialize the subtree pointers */
static gint ett_fcp = -1;
static gint ett_fcp_taskmgmt = -1;
static gint ett_fcp_rsp_flags = -1;

static dissector_table_t fcp_dissector;
static dissector_handle_t data_handle;

/* Information Categories based on lower 4 bits of R_CTL */
#define FCP_IU_DATA              0x1
#define FCP_IU_CONFIRM           0x3
#define FCP_IU_XFER_RDY          0x5
#define FCP_IU_CMD               0x6
#define FCP_IU_RSP               0x7

static const value_string fcp_iu_val[] = {
    {FCP_IU_DATA      , "FCP_DATA"},
    {FCP_IU_CONFIRM   , "Confirm"},
    {FCP_IU_XFER_RDY  , "XFER_RDY"},
    {FCP_IU_CMD       , "FCP_CMND"},
    {FCP_IU_RSP       , "FCP_RSP"},
    {0, NULL},
};


/* Task Attribute Values */
static const value_string fcp_task_attr_val[] = {
    {0, "Simple"},
    {1, "Head of Queue"},
    {2, "Ordered"},
    {4, "ACA"},
    {5, "Untagged"},
    {0, NULL},
};

/* RSP Code Definitions (from FCP_RSP_INFO) */
static const value_string fcp_rsp_code_val[] = {
    {0, "Task Management Function Complete"},
    {1, "FCP_DATA length Different from FCP_BURST_LEN"},
    {2, "FCP_CMND Fields Invalid"},
    {3, "FCP_DATA Parameter Mismatch With FCP_DATA_RO"},
    {4, "Task Management Function Rejected"},
    {5, "Task Management Function Failed"},
    {9, "Task Management Function Incorrect LUN"},
    {0, NULL},
};


typedef struct _fcp_conv_key {
    guint32 conv_idx;
} fcp_conv_key_t;

typedef struct _fcp_conv_data {
    gint32 fcp_lun;
} fcp_conv_data_t;

GHashTable *fcp_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcp_equal(gconstpointer v, gconstpointer w)
{
  const fcp_conv_key_t *v1 = v;
  const fcp_conv_key_t *v2 = w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcp_hash (gconstpointer v)
{
	const fcp_conv_key_t *key = v;
	guint val;

	val = key->conv_idx;

	return val;
}

/*
 * Protocol initialization
 */
static void
fcp_init_protocol(void)
{
    if (fcp_req_hash)
        g_hash_table_destroy(fcp_req_hash);

    fcp_req_hash = g_hash_table_new(fcp_hash, fcp_equal);
}

static const true_false_string fcp_mgmt_flags_obsolete_tfs = {
   "OBSOLETE BIT is SET",
   "OBSOLETE BIT is NOT set",
};
static const true_false_string fcp_mgmt_flags_clear_aca_tfs = {
   "CLEAR ACA is SET",
   "Clear aca is NOT set",
};
static const true_false_string fcp_mgmt_flags_target_reset_tfs = {
   "TARGET RESET is SET",
   "Target reset is NOT set",
};
static const true_false_string fcp_mgmt_flags_lu_reset_tfs = {
   "LU RESET is SET",
   "Lu reset is NOT set",
};
static const true_false_string fcp_mgmt_flags_rsvd_tfs = {
   "RSVD is SET",
   "Rsvd is NOT set",
};
static const true_false_string fcp_mgmt_flags_clear_task_set_tfs = {
   "CLEAR TASK SET is SET",
   "Clear task set is NOT set",
};
static const true_false_string fcp_mgmt_flags_abort_task_set_tfs = {
   "ABORT TASK SET is SET",
   "Abort task set is NOT set",
};

static void
dissect_task_mgmt_flags (packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint8 flags;

	if(parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_fcp_taskmgmt, tvb, offset, 1, TRUE);
		tree = proto_item_add_subtree(item, ett_fcp_taskmgmt);
	}

	flags = tvb_get_guint8 (tvb, offset);

	if (!flags)
		proto_item_append_text(item, " (No values set)");
				
	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_obsolete, tvb, offset, 1, flags);
	if (flags&0x80){
		proto_item_append_text(item, "  OBSOLETE");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP OBSOLETE] ");
		}
	}
	flags&=(~( 0x80 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_clear_aca, tvb, offset, 1, flags);
	if (flags&0x40){
		proto_item_append_text(item, "  CLEAR ACA");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP CLEAR_ACA] ");
		}
	}
	flags&=(~( 0x40 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_target_reset, tvb, offset, 1, flags);
	if (flags&0x20){
		proto_item_append_text(item, "  TARGET RESET");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP TARGET_RESET] ");
		}
	}
	flags&=(~( 0x20 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_lu_reset, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, "  LU RESET");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP LU_RESET] ");
		}
	}
	flags&=(~( 0x10 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_rsvd, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, "  RSVD");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP RSVD] ");
		}
	}
	flags&=(~( 0x08 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_clear_task_set, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, "  CLEAR TASK SET");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP CLEAR_TASK_SET] ");
		}
	}
	flags&=(~( 0x04 ));

	proto_tree_add_boolean(tree, hf_fcp_mgmt_flags_abort_task_set, tvb, offset, 1, flags);
	if (flags&0x02){
		proto_item_append_text(item, "  ABORT TASK SET");
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[FCP ABORT_TASK_SET] ");
		}
	}
	flags&=(~( 0x02 ));

	if(flags){
		proto_item_append_text(item, " Unknown bitmap value 0x%x", flags);
	}
}

static const true_false_string fcp_rsp_flags_bidi_tfs = {
   "Bidirectional residual fields are PRESENT",
   "Bidirectional residual fields are NOT present",
};
static const true_false_string fcp_rsp_flags_bidi_rru_tfs = {
   "Bidirectional residual underflow is PRESENT",
   "Bidirectional residual underflow is NOT present",
};
static const true_false_string fcp_rsp_flags_bidi_rro_tfs = {
   "Bidirectional residual overflow is PRESENT",
   "Bidirectional residual overflow is NOT present",
};
static const true_false_string fcp_rsp_flags_conf_req_tfs = {
   "CONF REQ is SET",
   "Conf req set is NOT set",
};
static const true_false_string fcp_rsp_flags_resid_under_tfs = {
   "RESID UNDER is SET",
   "Resid under is NOT set",
};
static const true_false_string fcp_rsp_flags_resid_over_tfs = {
   "RESID OVER is SET",
   "Resid over is NOT set",
};
static const true_false_string fcp_rsp_flags_sns_vld_tfs = {
   "SNS VLD is SET",
   "Sns vld is NOT set",
};
static const true_false_string fcp_rsp_flags_res_vld_tfs = {
   "RES VLD is SET",
   "Res vld is NOT set",
};

static void
dissect_rsp_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	gboolean bidi_resid_present=FALSE;
	guint8 flags;

	if(parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_fcp_rspflags, tvb, offset, 1, TRUE);
		tree = proto_item_add_subtree(item, ett_fcp_rsp_flags);
	}

	flags = tvb_get_guint8 (tvb, offset);

	if (!flags)
		proto_item_append_text(item, " (No values set)");

	/* BIDI RSP */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_bidi, tvb, offset, 1, flags);
	if (flags&0x80){
		bidi_resid_present=TRUE;
		proto_item_append_text(item, " BIDI_RSP");
		if (flags & (~( 0x80 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x80 ));

	/* these two bits are only defined if the bidi bit is set */
	if(bidi_resid_present){
		/* BIDI READ RESID UNDER */
		proto_tree_add_boolean(tree, hf_fcp_rsp_flags_bidi_rru, tvb, offset, 1, flags);
		if (flags&0x40){
			proto_item_append_text(item, " BIDI_RRU");
			if (flags & (~( 0x40 )))
				proto_item_append_text(item, ",");
		}
		flags&=(~( 0x40 ));

		/* BIDI READ RESID OVER */
		proto_tree_add_boolean(tree, hf_fcp_rsp_flags_bidi_rro, tvb, offset, 1, flags);
		if (flags&0x20){
			proto_item_append_text(item, " BIDI_RRO");
			if (flags & (~( 0x20 )))
				proto_item_append_text(item, ",");
		}
		flags&=(~( 0x20 ));
	}

	/* Conf Req */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_conf_req, tvb, offset, 1, flags);
	if (flags&0x10){
		proto_item_append_text(item, " CONF REQ");
		if (flags & (~( 0x10 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x10 ));

	/* Resid Under */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_resid_under, tvb, offset, 1, flags);
	if (flags&0x08){
		proto_item_append_text(item, " RESID UNDER");
		if (flags & (~( 0x08 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x08 ));

	/* Resid Over */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_resid_over, tvb, offset, 1, flags);
	if (flags&0x04){
		proto_item_append_text(item, " RESID OVER");
		if (flags & (~( 0x04 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x04 ));

	/* SNS len valid */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_sns_vld, tvb, offset, 1, flags);
	if (flags&0x02){
		proto_item_append_text(item, " SNS VLD");
		if (flags & (~( 0x02 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x02 ));

	/* rsp len valid */
	proto_tree_add_boolean(tree, hf_fcp_rsp_flags_res_vld, tvb, offset, 1, flags);
	if (flags&0x01){
		proto_item_append_text(item, " RES VLD");
		if (flags & (~( 0x01 )))
			proto_item_append_text(item, ",");
	}
	flags&=(~( 0x01 ));

	if(flags){
		proto_item_append_text(item, " Unknown bitmap value 0x%x", flags);
	}
}

/* Code to actually dissect the packets */
static void
dissect_fcp_cmnd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, proto_tree *tree, conversation_t *conversation)
{
    int offset = 0;
    int len,
        add_len = 0;
    guint8 flags, lun0;
    fcp_conv_data_t *cdata;
    fcp_conv_key_t ckey, *req_key;
    scsi_task_id_t task_key;
    guint16 lun=0xffff;
    tvbuff_t *cdb_tvb;
    int tvb_len, tvb_rlen;

    /* Determine the length of the FCP part of the packet */
    flags = tvb_get_guint8 (tvb, offset+10);
    if (flags) {
        add_len = tvb_get_guint8 (tvb, offset+11) & 0x7C;
        add_len = add_len >> 2;

        len = FCP_DEF_CMND_LEN + add_len;
    }
    else {
        len = FCP_DEF_CMND_LEN;
    }

    /* We use conversations to track how many bytes are required in the data
     * part of the transaction.
     * This state is later destroyed when we see the response.
     * XXX this is broken and can only work for single scan of the capture file
     */
    ckey.conv_idx = conversation->index;
    task_key.conv_id = conversation->index;
    task_key.task_id = conversation->index;
    pinfo->private_data = (void *)&task_key;

    cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                    &ckey);
    /*
     * XXX - the fetch of the fcp_dl value will throw an exception on
     * a short frame before we get a chance to dissect the stuff before
     * it.
     */
    if (!cdata) {
        req_key = se_alloc (sizeof(fcp_conv_key_t));
        req_key->conv_idx = conversation->index;

        cdata = se_alloc (sizeof(fcp_conv_data_t));
        g_hash_table_insert (fcp_req_hash, req_key, cdata);
    }

    /* XXX this one is redundant  right?  ronnie
    dissect_scsi_cdb (tvb, pinfo, tree, offset+12, 16+add_len,
                      SCSI_DEV_UNKNOWN, lun);
    */

    proto_tree_add_uint_hidden(tree, hf_fcp_type, tvb, offset, 0, 0);

    lun0 = tvb_get_guint8 (tvb, offset);

    /* Display single-level LUNs in decimal for clarity */
    /* I'm taking a shortcut here by assuming that if the first byte of the
     * LUN field is 0, it is a single-level LUN. This is not true. For a
     * real single-level LUN, all 8 bytes except byte 1 must be 0.
     */
    if (lun0) {
      cdata->fcp_lun = -1;
      proto_tree_add_item(tree, hf_fcp_multilun, tvb, offset, 8, 0);
      lun=tvb_get_guint8(tvb, offset)&0x3f;
      lun<<=8;
      lun|=tvb_get_guint8(tvb, offset+1);
    }
    else {
      cdata->fcp_lun = tvb_get_guint8 (tvb, offset+1);
      proto_tree_add_item(tree, hf_fcp_singlelun, tvb, offset+1,
			   1, 0);
      lun=tvb_get_guint8(tvb, offset+1);
    }

    proto_tree_add_item(tree, hf_fcp_crn, tvb, offset+8, 1, 0);
    proto_tree_add_item(tree, hf_fcp_taskattr, tvb, offset+9, 1, 0);
    dissect_task_mgmt_flags(pinfo, tree, tvb, offset+10);
    proto_tree_add_item(tree, hf_fcp_addlcdblen, tvb, offset+11, 1, 0);
    proto_tree_add_item(tree, hf_fcp_rddata, tvb, offset+11, 1, 0);
    proto_tree_add_item(tree, hf_fcp_wrdata, tvb, offset+11, 1, 0);

    tvb_len=tvb_length_remaining(tvb, offset+12);
    if(tvb_len>(16+add_len))
      tvb_len=16+add_len;
    tvb_rlen=tvb_reported_length_remaining(tvb, offset+12);
    if(tvb_rlen>(16+add_len))
      tvb_rlen=16+add_len;
    cdb_tvb=tvb_new_subset(tvb, offset+12, tvb_len, tvb_rlen);
    dissect_scsi_cdb(cdb_tvb, pinfo, parent_tree, SCSI_DEV_UNKNOWN, lun);

    proto_tree_add_item(tree, hf_fcp_dl, tvb, offset+12+16+add_len,
			 4, 0);
}

static void
dissect_fcp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, proto_tree *tree, conversation_t *conversation)
{
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey;
    scsi_task_id_t task_key;

    /* use conversations to find the expected payload */
    ckey.conv_idx = conversation->index;

    cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
    task_key.conv_id = conversation->index;
    task_key.task_id = conversation->index;
    pinfo->private_data = (void *)&task_key;

    if (cdata) {
        if (cdata->fcp_lun >= 0)
            proto_tree_add_uint_hidden(tree, hf_fcp_singlelun, tvb,
                                        0, 0, cdata->fcp_lun);

        dissect_scsi_payload(tvb, pinfo, parent_tree, FALSE, (guint16) cdata->fcp_lun);
    } else {
        dissect_scsi_payload(tvb, pinfo, parent_tree, FALSE, 0xffff);
    }
}

/* fcp-3  9.5 table 24 */
static void
dissect_fcp_rspinfo(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* 2 reserved bytes */
	offset+=2;

        /* rsp code */
	proto_tree_add_item(tree, hf_fcp_rspcode, tvb, offset, 1, 0);
	offset++;

        /* 4 reserved bytes */
	offset+=4;
}

static void
dissect_fcp_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, proto_tree *tree, conversation_t *conversation)
{
    guint32 offset = 0;
    gint32 snslen = 0,
           rsplen = 0;
    guint8 flags;
    guint8 status;
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey;
    scsi_task_id_t task_key;

    status = tvb_get_guint8 (tvb, offset+11);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":%s",
                         val_to_str (status, scsi_status_val, "0x%x"));
    }

    /* Response marks the end of the conversation. So destroy state */
    if (conversation) {
        ckey.conv_idx = conversation->index;

        cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
        task_key.conv_id = task_key.task_id = conversation->index;
        pinfo->private_data = (void *)&task_key;
    }

    proto_tree_add_uint_hidden(tree, hf_fcp_type, tvb, offset, 0, 0);



        /* 8 reserved bytes */
        offset+=8;

        /* retry delay timer */
        proto_tree_add_item(tree, hf_fcp_retry_delay_timer, tvb, offset, 2, 0);
        offset+=2;

        /* flags */
        flags = tvb_get_guint8 (tvb, offset);
        dissect_rsp_flags(tree, tvb, offset);
        offset++;

        /* scsi status code */
        proto_tree_add_item(tree, hf_fcp_scsistatus, tvb, offset, 1, 0);
        if(cdata){
            dissect_scsi_rsp(tvb, pinfo, parent_tree, (guint16) cdata->fcp_lun, tvb_get_guint8(tvb, offset));
        }
        offset++;

        /* residual count */
        if(flags & 0x0e){
            proto_tree_add_item(tree, hf_fcp_resid, tvb, offset, 4, 0);
        }
        offset+=4;

        /* sense length */
        if (flags & 0x2) {
            snslen=tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(tree, hf_fcp_snslen, tvb, offset, 4,
                                 snslen);
        }
        offset+=4;

        /* response length */
        if (flags & 0x1) {
            rsplen=tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(tree, hf_fcp_rsplen, tvb, offset, 4,
                                 rsplen);
        }
        offset+=4;

        /* rsp_info */
        if(rsplen){
            tvbuff_t *rspinfo_tvb;
       
            rspinfo_tvb=tvb_new_subset(tvb, offset, MIN(rsplen, tvb_length_remaining(tvb, offset)), rsplen);
            dissect_fcp_rspinfo(tvb, tree, 0);

            offset+=rsplen;
        }

        /* sense info */
        if(snslen){
            tvbuff_t *sns_tvb;
       
            sns_tvb=tvb_new_subset(tvb, offset, MIN(snslen, tvb_length_remaining(tvb, offset)), snslen);
            dissect_scsi_snsinfo (sns_tvb, pinfo, parent_tree, 0,
                                  snslen,
				  (guint16) (cdata?cdata->fcp_lun:0xffff) );

            offset+=snslen;
        }

        /* bidir read resid (only present for bidirectional responses) */
        if(flags&0x80){
            if(flags&0x60){
                proto_tree_add_item(tree, hf_fcp_bidir_resid, tvb, offset, 4, 0);
            }
            offset+=4;
        }


        if (cdata) {
            /*
             * XXX - this isn't done if an exception is thrown.
             */
            g_hash_table_remove (fcp_req_hash, &ckey);
        }
}

static void
dissect_fcp_xfer_rdy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, proto_tree *tree, conversation_t *conversation)
{
    int offset = 0;
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey, *req_key;


    /* use conversation state to determine expected payload */
    if (!conversation) {
        conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         pinfo->ptype, pinfo->oxid,
                                         pinfo->rxid, NO_PORT2);
    }

    if (conversation) {
        ckey.conv_idx = conversation->index;

        cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
        if (!cdata) {
            req_key = se_alloc (sizeof(fcp_conv_key_t));
            req_key->conv_idx = conversation->index;

            cdata = se_alloc (sizeof(fcp_conv_data_t));
            cdata->fcp_lun = -1;

            g_hash_table_insert (fcp_req_hash, req_key, cdata);
        }
    }

    proto_tree_add_uint_hidden(tree, hf_fcp_type, tvb, offset, 0, 0);

    proto_tree_add_item(tree, hf_fcp_data_ro, tvb, offset, 4, 0);
    proto_tree_add_item(tree, hf_fcp_burstlen, tvb, offset+4, 4, 0);
}

static void
dissect_fcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *fcp_tree = NULL;
    conversation_t *conversation;

/* Set up structures needed to add the protocol subtree and manage it */
    guint8 r_ctl;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FCP");

    r_ctl = pinfo->r_ctl;

    r_ctl &= 0xF;

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_set_str (pinfo->cinfo, COL_INFO, val_to_str (r_ctl, fcp_iu_val,
                                                      "0x%x"));
    }


    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_fcp, tvb, 0, -1,
                                             "FCP: %s", val_to_str(r_ctl, fcp_iu_val, "Unknown 0x%02x"));
        fcp_tree = proto_item_add_subtree(ti, ett_fcp);
    }


    /* find the conversation for this transaction and create a new one if it 
     * doesnt exist already.
     * XXX since FCP is always transported atop FC and FC also keeps track of
     * transactions we should grab the conversation off FC instead
     * we guarantee that conversation is non-NULL so the helpers we call
     * do not need to check it before dereferencing.
     */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->oxid,
                                      pinfo->rxid, NO_PORT2);
    if (!conversation) {
	/* NO_PORT2: Dont check RXID, iFCP traces i have all have 
	 * RXID==0xffff in the command PDU.   ronnie */
        conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         pinfo->ptype, pinfo->oxid,
                                         pinfo->rxid, NO_PORT2);
    }


    switch (r_ctl) {
    case FCP_IU_DATA:
        dissect_fcp_data(tvb, pinfo, tree, fcp_tree, conversation);
        break;
    case FCP_IU_CONFIRM:
        /* Nothing to be done here */
        break;
    case FCP_IU_XFER_RDY:
        dissect_fcp_xfer_rdy(tvb, pinfo, tree, fcp_tree, conversation);
        break;
    case FCP_IU_CMD:
        dissect_fcp_cmnd(tvb, pinfo, tree, fcp_tree, conversation);
        break;
    case FCP_IU_RSP:
        dissect_fcp_rsp(tvb, pinfo, tree, fcp_tree, conversation);
        break;
    default:
        call_dissector(data_handle, tvb, pinfo, tree);
        break;
    }
/*xxx once the subdissectors return bytes consumed:  proto_item_set_end(ti, tvb, offset);*/

}

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fcp (void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fcp_type,
          {"Field to branch off to SCSI", "fcp.type", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        {&hf_fcp_multilun,
         {"Multi-Level LUN", "fcp.multilun", FT_BYTES, BASE_HEX, NULL, 0x0,
          "", HFILL}},
        { &hf_fcp_singlelun,
          {"LUN", "fcp.lun", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcp_crn,
          {"Command Ref Num", "fcp.crn", FT_UINT8, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_taskattr,
          {"Task Attribute", "fcp.taskattr", FT_UINT8, BASE_HEX,
           VALS (fcp_task_attr_val), 0x7, "", HFILL}},
        { &hf_fcp_taskmgmt,
          {"Task Management Flags", "fcp.taskmgmt", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fcp_addlcdblen,
          {"Additional CDB Length", "fcp.addlcdblen", FT_UINT8, BASE_DEC, NULL,
           0xFC, "", HFILL}},
        { &hf_fcp_rddata,
          {"RDDATA", "fcp.rddata", FT_BOOLEAN, 8, NULL, 0x02, "", HFILL}},
        { &hf_fcp_wrdata,
          {"WRDATA", "fcp.wrdata", FT_BOOLEAN, 8, NULL, 0x01, "", HFILL}},
        { &hf_fcp_dl,
          {"FCP_DL", "fcp.dl", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcp_data_ro,
          {"FCP_DATA_RO", "fcp.data_ro", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_burstlen,
          {"Burst Length", "fcp.burstlen", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_retry_delay_timer,
          {"Retry Delay Timer", "fcp.rsp.retry_delay_timer", FT_UINT16, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_rspflags,
          {"FCP_RSP Flags", "fcp.rspflags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_resid,
          {"FCP_RESID", "fcp.resid", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_bidir_resid,
          {"Bidirectional Read Resid", "fcp.bidir_resid", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_snslen,
          {"FCP_SNS_LEN", "fcp.snslen", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_rsplen,
          {"FCP_RSP_LEN", "fcp.rsplen", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_rspcode,
          {"RSP_CODE", "fcp.rspcode", FT_UINT8, BASE_HEX,
           VALS (fcp_rsp_code_val), 0x0, "", HFILL}},
        { &hf_fcp_scsistatus,
          {"SCSI Status", "fcp.status", FT_UINT8, BASE_HEX,
           VALS (scsi_status_val), 0x0, "", HFILL}},
	{ &hf_fcp_mgmt_flags_obsolete, 
	  { "Obsolete", "fcp.mgmt.flags.obsolete", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_obsolete_tfs), 0x80, "", HFILL }},
	{ &hf_fcp_mgmt_flags_clear_aca, 
	  { "Clear ACA", "fcp.mgmt.flags.clear_aca", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_clear_aca_tfs), 0x40, "", HFILL }},
	{ &hf_fcp_mgmt_flags_target_reset, 
	  { "Target Reset", "fcp.mgmt.flags.target_reset", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_target_reset_tfs), 0x20, "", HFILL }},
	{ &hf_fcp_mgmt_flags_lu_reset, 
	  { "LU Reset", "fcp.mgmt.flags.lu_reset", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_lu_reset_tfs), 0x10, "", HFILL }},
	{ &hf_fcp_mgmt_flags_rsvd, 
	  { "Rsvd", "fcp.mgmt.flags.rsvd", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_rsvd_tfs), 0x08, "", HFILL }},
	{ &hf_fcp_mgmt_flags_clear_task_set, 
	  { "Clear Task Set", "fcp.mgmt.flags.clear_task_set", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_clear_task_set_tfs), 0x04, "", HFILL }},
	{ &hf_fcp_mgmt_flags_abort_task_set, 
	  { "Abort Task Set", "fcp.mgmt.flags.abort_task_set", FT_BOOLEAN, 8, TFS(&fcp_mgmt_flags_abort_task_set_tfs), 0x02, "", HFILL }},
	{ &hf_fcp_rsp_flags_bidi, 
	  { "Bidi Rsp", "fcp.rsp.flags.bidi", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_bidi_tfs), 0x80, "", HFILL }},
	{ &hf_fcp_rsp_flags_bidi_rru, 
	  { "Bidi Read Resid Under", "fcp.rsp.flags.bidi_rru", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_bidi_rru_tfs), 0x40, "", HFILL }},
	{ &hf_fcp_rsp_flags_bidi_rro, 
	  { "Bidi Read Resid Over", "fcp.rsp.flags.bidi_rro", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_bidi_rro_tfs), 0x20, "", HFILL }},
	{ &hf_fcp_rsp_flags_conf_req, 
	  { "Conf Req", "fcp.rsp.flags.conf_req", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_conf_req_tfs), 0x10, "", HFILL }},
	{ &hf_fcp_rsp_flags_resid_under, 
	  { "Resid Under", "fcp.rsp.flags.resid_under", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_resid_under_tfs), 0x08, "", HFILL }},
	{ &hf_fcp_rsp_flags_resid_over, 
	  { "Resid Over", "fcp.rsp.flags.resid_over", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_resid_over_tfs), 0x04, "", HFILL }},
	{ &hf_fcp_rsp_flags_sns_vld, 
	  { "SNS Vld", "fcp.rsp.flags.sns_vld", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_sns_vld_tfs), 0x02, "", HFILL }},
	{ &hf_fcp_rsp_flags_res_vld, 
	  { "RES Vld", "fcp.rsp.flags.res_vld", FT_BOOLEAN, 8, TFS(&fcp_rsp_flags_res_vld_tfs), 0x01, "", HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fcp,
	&ett_fcp_taskmgmt,
	&ett_fcp_rsp_flags,
    };

    /* Register the protocol name and description */
    proto_fcp = proto_register_protocol("Fibre Channel Protocol for SCSI",
                                        "FCP", "fcp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    fcp_dissector = register_dissector_table ("fcp.type", "FCP Type", FT_UINT8,
                                              BASE_HEX);
    register_init_routine (&fcp_init_protocol);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fcp (void)
{
    dissector_handle_t fcp_handle;

    fcp_handle = create_dissector_handle (dissect_fcp, proto_fcp);
    dissector_add("fc.ftype", FC_FTYPE_SCSI, fcp_handle);

    data_handle = find_dissector ("data");
}
