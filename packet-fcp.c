/* packet-fcp.c
 * Routines for Fibre Channel Protocol for SCSI (FCP)
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id: packet-fcp.c,v 1.1 2002/12/08 02:32:17 gerald Exp $
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "prefs.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include "etypes.h"
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
static int hf_fcp_resid      = -1;
static int hf_fcp_snslen     = -1;
static int hf_fcp_rsplen     = -1;
static int hf_fcp_rspcode    = -1;
static int hf_fcp_scsistatus = -1;
static int hf_fcp_type = -1;


/* Initialize the subtree pointers */
static gint ett_fcp = -1;
static dissector_table_t fcp_dissector;
static dissector_handle_t data_handle;

typedef struct _fcp_conv_key {
    guint32 conv_idx;
} fcp_conv_key_t;

typedef struct _fcp_conv_data {
    guint32 fcp_dl;
    gint32 fcp_lun;
    guint32 abs_secs;
    guint32 abs_usecs;
} fcp_conv_data_t;

GHashTable *fcp_req_hash = NULL;
GMemChunk *fcp_req_keys = NULL;
GMemChunk *fcp_req_vals = NULL;
guint32 fcp_init_count = 25;

/*
 * Hash Functions
 */
static gint
fcp_equal(gconstpointer v, gconstpointer w)
{
  fcp_conv_key_t *v1 = (fcp_conv_key_t *)v;
  fcp_conv_key_t *v2 = (fcp_conv_key_t *)w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcp_hash (gconstpointer v)
{
	fcp_conv_key_t *key = (fcp_conv_key_t *)v;
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
    if (fcp_req_keys)
        g_mem_chunk_destroy(fcp_req_keys);
    if (fcp_req_vals)
        g_mem_chunk_destroy(fcp_req_vals);
    if (fcp_req_hash)
        g_hash_table_destroy(fcp_req_hash);

    fcp_req_hash = g_hash_table_new(fcp_hash, fcp_equal);
    fcp_req_keys = g_mem_chunk_new("fcp_req_keys",
                                   sizeof(fcp_conv_key_t),
                                   fcp_init_count * sizeof(fcp_conv_key_t),
                                   G_ALLOC_AND_FREE);
    fcp_req_vals = g_mem_chunk_new("fcp_req_vals",
                                   sizeof(fcp_conv_data_t),
                                   fcp_init_count * sizeof(fcp_conv_data_t),
                                   G_ALLOC_AND_FREE);
}

static gchar *
task_mgmt_flags_to_str (guint8 flags, gchar *str)
{
    int stroff = 0;
    
    if (str == NULL)
        return str;

    *str = '\0';
    
    if (flags & 0x80) {
        strcpy (str, "Obsolete, ");
        stroff += 10;
    }

    if (flags & 0x40) {
        strcpy (&str[stroff], "Clear ACA, ");
        stroff += 11;
    }

    if (flags & 0x20) {
        strcpy (&str[stroff], "Target Reset, ");
        stroff += 14;
    }

    if (flags & 0x10) {
        strcpy (&str[stroff], "LU Reset, ");
        stroff += 10;
    }

    if (flags & 0x08) {
        strcpy (&str[stroff], "Rsvd, ");
        stroff += 6;
    }

    if (flags & 0x04) {
        strcpy (&str[stroff], "Clear Task Set, ");
        stroff += 16;
    }

    if (flags & 0x02) {
        strcpy (&str[stroff], "Abort Task Set");
        stroff += 14;
    }

    return (str);
}

static gchar *
rspflags_to_str (guint8 flags, gchar *str)
{
    int stroff = 0;

    if (str == NULL)
        return (str);

    *str = '\0';
    
    if (flags & 0x10) {
        strcpy (str, "FCP_CONF_REQ | ");
        stroff += 15;
    }
    if (flags & 0x08) {
        strcpy (&str[stroff], "FCP_RESID_UNDER | ");
        stroff += 18;
    }
    if (flags & 0x04) {
        strcpy (&str[stroff], "FCP_RESID_OVER | ");
        stroff += 17;
    }
    if (flags & 0x02) {
        strcpy (&str[stroff], "FCP_SNS_LEN_VLD | ");
        stroff += 18;
    }
    if (flags & 0x01) {
        strcpy (&str[stroff], "FCP_RSP_LEN_VLD | ");
    }

    return (str);
}

/* Code to actually dissect the packets */
static void
dissect_fcp_cmnd (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int len,
        add_len = 0;
    gchar str[128];
    guint8 flags, lun0;
    proto_item *ti;
    proto_tree *fcp_tree = NULL;
    conversation_t *conversation;
    fcp_conv_data_t *cdata;
    fcp_conv_key_t ckey, *req_key;
    scsi_task_id_t task_key;

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

    /* We track the conversation to determine how many bytes is required */
    /* by the data that is sent back or sent next by the initiator as part */
    /* of this command. The state is destroyed in the response dissector */
    
    conversation = find_conversation (&pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->oxid,
                                      pinfo->rxid, NO_PORT2);
    if (!conversation) {
        conversation = conversation_new (&pinfo->src, &pinfo->dst,
                                         pinfo->ptype, pinfo->oxid,
                                         pinfo->rxid, NO_PORT2);
    }
    
    ckey.conv_idx = conversation->index;
    task_key.conv_id = conversation->index;
    task_key.task_id = conversation->index;
    pinfo->private_data = (void *)&task_key;
    
    cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                    &ckey);
    if (cdata) {
        /* Since we never free the memory used by an exchange, this maybe a
         * case of another request using the same exchange as a previous
         * req. 
         */
        cdata->fcp_dl = tvb_get_ntohl (tvb, offset+12+16+add_len);
        cdata->abs_usecs = pinfo->fd->abs_usecs;
        cdata->abs_secs = pinfo->fd->abs_secs;
    }
    else {
        req_key = g_mem_chunk_alloc (fcp_req_keys);
        req_key->conv_idx = conversation->index;
        
        cdata = g_mem_chunk_alloc (fcp_req_vals);
        cdata->fcp_dl = tvb_get_ntohl (tvb, offset+12+16+add_len);
        cdata->abs_usecs = pinfo->fd->abs_usecs;
        cdata->abs_secs = pinfo->fd->abs_secs;
        
        g_hash_table_insert (fcp_req_hash, req_key, cdata);
    }
    
    dissect_scsi_cdb (tvb, pinfo, fcp_tree, offset+12, 16+add_len,
                      SCSI_DEV_UNKNOWN);

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fcp, tvb, 0, len,
                                             "FCP_CMND");
        fcp_tree = proto_item_add_subtree (ti, ett_fcp);
        proto_tree_add_uint_hidden (fcp_tree, hf_fcp_type, tvb, offset, 0, 0);
                                    
        lun0 = tvb_get_guint8 (tvb, offset);

        /* Display single-level LUNs in decimal for clarity */
        /* I'm taking a shortcut here by assuming that if the first byte of the
         * LUN field is 0, it is a single-level LUN. This is not true. For a
         * real single-level LUN, all 8 bytes except byte 1 must be 0.
         */
        if (lun0) {
            cdata->fcp_lun = -1;
            proto_tree_add_item (fcp_tree, hf_fcp_multilun, tvb, offset, 8, 0);
        }
        else {
            cdata->fcp_lun = tvb_get_guint8 (tvb, offset+1);
            proto_tree_add_item (fcp_tree, hf_fcp_singlelun, tvb, offset+1,
                                 1, 0);
        }

        proto_tree_add_item (fcp_tree, hf_fcp_crn, tvb, offset+8, 1, 0);
        proto_tree_add_item (fcp_tree, hf_fcp_taskattr, tvb, offset+9, 1, 0);
        proto_tree_add_uint_format (fcp_tree, hf_fcp_taskmgmt, tvb, offset+10,
                                    1, flags,
                                    "Task Management Flags: 0x%x (%s)",
                                    flags,
                                    task_mgmt_flags_to_str (flags, str));
        proto_tree_add_item (fcp_tree, hf_fcp_addlcdblen, tvb, offset+11, 1, 0);
        proto_tree_add_item (fcp_tree, hf_fcp_rddata, tvb, offset+11, 1, 0);
        proto_tree_add_item (fcp_tree, hf_fcp_wrdata, tvb, offset+11, 1, 0);
        dissect_scsi_cdb (tvb, pinfo, tree, offset+12, 16+add_len,
                          SCSI_DEV_UNKNOWN);
        proto_tree_add_item (fcp_tree, hf_fcp_dl, tvb, offset+12+16+add_len,
                             4, 0);
    }
}

static void
dissect_fcp_data (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    conversation_t *conversation;
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey;
    proto_item *ti;
    proto_tree *fcp_tree;
    scsi_task_id_t task_key;

    /* Retrieve conversation state to determine expected payload */
    conversation = find_conversation (&pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->oxid,
                                      pinfo->rxid, NO_PORT2);
    if (conversation) {
        ckey.conv_idx = conversation->index;
    
        cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
        task_key.conv_id = conversation->index;
        task_key.task_id = conversation->index;
        pinfo->private_data = (void *)&task_key;
    }
    else {
        pinfo->private_data = NULL;
    }
    if (cdata) {
        ti = proto_tree_add_protocol_format (tree, proto_fcp, tvb, 0, 0,
                                             "FCP_DATA");
        fcp_tree = proto_item_add_subtree (ti, ett_fcp);

        if (cdata->fcp_lun >= 0)
            proto_tree_add_uint_hidden (fcp_tree, hf_fcp_singlelun, tvb,
                                        0, 0, cdata->fcp_lun);

        dissect_scsi_payload (tvb, pinfo, tree, 0, FALSE, cdata->fcp_dl);
    }
    else {
        dissect_scsi_payload (tvb, pinfo, tree, 0, FALSE, 0);
    }
}

static void
dissect_fcp_rsp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint32 offset = 0,
        del_usecs = 0;
    guint len = 0,
          add_len = 0,
          rsplen = 0;
    gchar str[128];
    guint8 flags;
    proto_item *ti;
    proto_tree *fcp_tree;
    guint8 status;
    conversation_t *conversation;
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey;
    scsi_task_id_t task_key;

    status = tvb_get_guint8 (tvb, offset+11);
    
    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_append_fstr (pinfo->cinfo, COL_INFO, " , %s",
                         val_to_str (status, scsi_status_val, "0x%x"));
    }

    /* Response marks the end of the conversation. So destroy state */
    conversation = find_conversation (&pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->oxid,
                                      pinfo->rxid, NO_PORT2);
    if (conversation) {
        ckey.conv_idx = conversation->index;
    
        cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
        task_key.conv_id = task_key.task_id = conversation->index;
        pinfo->private_data = (void *)&task_key;
    }
    
    if (tree) {
        /* Determine the length of the FCP part of the packet */
        len = FCP_DEF_RSP_LEN;

        flags = tvb_get_guint8 (tvb, offset+10);
        if (flags & 0x2) {
            add_len = tvb_get_ntohl (tvb, offset+20);
            len += add_len;
        }
        if (flags & 0x1) {
            add_len = tvb_get_ntohl (tvb, offset+16);
            len += add_len;
        }

        ti = proto_tree_add_protocol_format (tree, proto_fcp, tvb, 0, len,
                                             "FCP_RSP");
        fcp_tree = proto_item_add_subtree (ti, ett_fcp);
        proto_tree_add_uint_hidden (fcp_tree, hf_fcp_type, tvb, offset, 0, 0);

        if (cdata) {
            del_usecs = (pinfo->fd->abs_secs - cdata->abs_secs)* 1000000 +
                (pinfo->fd->abs_usecs - cdata->abs_usecs);
            if (del_usecs > 1000)
                proto_tree_add_text (fcp_tree, tvb, offset, 0,
                                     "Cmd Response Time: %d msecs",
                                     del_usecs/1000);
            else
                proto_tree_add_text (fcp_tree, tvb, offset, 0,
                                     "Cmd Response Time: %d usecs",
                                     del_usecs);
            if (cdata->fcp_lun >= 0)
                proto_tree_add_uint_hidden (fcp_tree, hf_fcp_singlelun, tvb,
                                            offset, 0, cdata->fcp_lun);
        }
        proto_tree_add_uint_format (fcp_tree, hf_fcp_rspflags, tvb, offset+10,
                                    1, flags, "Flags: 0x%x (%s)", flags,
                                    rspflags_to_str (flags, str));
        proto_tree_add_item (fcp_tree, hf_fcp_scsistatus, tvb, offset+11, 1, 0);
        if (flags & 0xC)
            proto_tree_add_item (fcp_tree, hf_fcp_resid, tvb, offset+12, 4, 0);
        if (flags & 0x2)
            proto_tree_add_item (fcp_tree, hf_fcp_snslen, tvb, offset+16, 4, 0);
        if (flags & 0x1) {
            rsplen = tvb_get_ntohl (tvb, offset+20);
            proto_tree_add_item (fcp_tree, hf_fcp_rsplen, tvb, offset+20, 4, 0);
            proto_tree_add_item (fcp_tree, hf_fcp_rspcode, tvb, offset+27, 1,
                                 0);
        }
        if (flags & 0x2) {
            dissect_scsi_snsinfo (tvb, pinfo, tree, offset+24+rsplen,
                                  tvb_get_ntohl (tvb, offset+16));
        }
        if (cdata) {
            g_mem_chunk_free (fcp_req_vals, cdata);
            g_hash_table_remove (fcp_req_hash, &ckey);
        }
    }
}

static void
dissect_fcp_xfer_rdy (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *fcp_tree;
    guint del_usecs;

    conversation_t *conversation;
    fcp_conv_data_t *cdata = NULL;
    fcp_conv_key_t ckey, *req_key;

    /* Retrieve conversation state to determine expected payload */
    conversation = find_conversation (&pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->oxid,
                                      pinfo->rxid, NO_PORT2);
    if (!conversation) {
        conversation = conversation_new (&pinfo->src, &pinfo->dst,
                                         pinfo->ptype, pinfo->oxid,
                                         pinfo->rxid, NO_PORT2);
    }
    
    if (conversation) {
        ckey.conv_idx = conversation->index;
    
        cdata = (fcp_conv_data_t *)g_hash_table_lookup (fcp_req_hash,
                                                        &ckey);
        if (cdata != NULL) {
            cdata->fcp_dl = tvb_get_ntohl (tvb, offset+4);
        }
        else {
            req_key = g_mem_chunk_alloc (fcp_req_keys);
            req_key->conv_idx = conversation->index;
            
            cdata = g_mem_chunk_alloc (fcp_req_vals);
            cdata->fcp_dl = tvb_get_ntohl (tvb, offset+4);
            cdata->fcp_lun = -1;
            
            g_hash_table_insert (fcp_req_hash, req_key, cdata);
        }
    }

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fcp, tvb, 0, 12,
                                             "FCP_XFER_RDY");
        fcp_tree = proto_item_add_subtree (ti, ett_fcp);
        proto_tree_add_uint_hidden (fcp_tree, hf_fcp_type, tvb, offset, 0, 0);

        if (cdata) {
            del_usecs = (pinfo->fd->abs_secs - cdata->abs_secs)* 1000000 +
                (pinfo->fd->abs_usecs - cdata->abs_usecs);
            if (del_usecs > 1000)
                proto_tree_add_text (fcp_tree, tvb, offset, 0,
                                     "Cmd Response Time: %d msecs",
                                     del_usecs/1000);
            else
                proto_tree_add_text (fcp_tree, tvb, offset, 0,
                                     "Cmd Response Time: %d usecs",
                                     del_usecs);
            if (cdata->fcp_lun >= 0)
                proto_tree_add_uint_hidden (fcp_tree, hf_fcp_singlelun, tvb,
                                            offset, 0, cdata->fcp_lun);
        }
        proto_tree_add_item (fcp_tree, hf_fcp_data_ro, tvb, offset, 4, 0);
        proto_tree_add_item (fcp_tree, hf_fcp_burstlen, tvb, offset+4, 4, 0);
    }
}

static void
dissect_fcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

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
    
    switch (r_ctl) {
    case FCP_IU_DATA:
        dissect_fcp_data (tvb, pinfo, tree);
        break;
    case FCP_IU_CONFIRM:
        /* Nothing to be done here */
        break;
    case FCP_IU_XFER_RDY:
        dissect_fcp_xfer_rdy (tvb, pinfo, tree);
        break;
    case FCP_IU_CMD:
        dissect_fcp_cmnd (tvb, pinfo, tree);
        break;
    case FCP_IU_RSP:
        dissect_fcp_rsp (tvb, pinfo, tree);
        break;
    default:
        call_dissector (data_handle, tvb, pinfo, tree);
        break;
    }
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
          {"RDDATA", "fcp.rddata", FT_UINT8, BASE_BIN, NULL, 0x2, "", HFILL}},
        { &hf_fcp_wrdata,
          {"WRDATA", "fcp.wrdata", FT_UINT8, BASE_BIN, NULL, 0x1, "", HFILL}},
        { &hf_fcp_dl,
          {"FCP_DL", "fcp.dl", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_fcp_data_ro,
          {"FCP_DATA_RO", "fcp.data_ro", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_burstlen,
          {"Burst Length", "fcp.burstlen", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_rspflags,
          {"FCP_RSP Flags", "fcp.rspflags", FT_UINT8, BASE_BIN, NULL, 0x0, "",
           HFILL}},
        { &hf_fcp_resid,
          {"FCP_RESID", "fcp.resid", FT_UINT32, BASE_DEC, NULL, 0x0, "",
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fcp,
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


