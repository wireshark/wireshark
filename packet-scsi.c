/* packet-scsi.c
 * Routines for decoding SCSI CDBs and responses
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-scsi.c,v 1.2 2002/01/16 20:25:07 guy Exp $
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
 * - The SCSI CDB is typically embedded inside the transport alongwith other
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
 * provide a unique way to determine a SCSI task. In Fibre channel networks,
 * this is the exchange ID pair alongwith the source/destination addresses; in
 * iSCSI it is the initiator task tag along with the src/dst address and port
 * numbers. This is to be provided to the SCSI decoder via the private_data
 * field in the packet_info data structure. The private_data field is treated
 * as a 32-bit field to uniquely identify a SCSI task. 
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
#include "strutil.h"
#include "conversation.h"
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


static gint ett_scsi         = -1;
static gint ett_scsi_page    = -1;
static gint scsi_def_devtype = SCSI_DEV_SBC;

/* The next two structures are used to track SCSI req/rsp */ 
typedef struct _scsi_task_key {
    guint32 conv_idx;
} scsi_task_key_t;

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
  scsi_task_key_t *v1 = (scsi_task_key_t *)v;
  scsi_task_key_t *v2 = (scsi_task_key_t *)w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
scsi_hash (gconstpointer v)
{
	scsi_task_key_t *key = (scsi_task_key_t *)v;
	guint val;

	val = key->conv_idx;

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
    scsi_task_key_t ckey, *req_key;
    conversation_t *conversation;
    
    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey.conv_idx = (guint32)pinfo->private_data;

        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
        if (!cdata) {
            req_key = g_mem_chunk_alloc (scsi_req_keys);
            req_key->conv_idx = (guint32 )pinfo->private_data;
            
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
    scsi_task_key_t ckey, *req_key;
    conversation_t *conversation;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey.conv_idx = (guint32)pinfo->private_data;

        cdata = (scsi_task_data_t *)g_hash_table_lookup (scsi_req_hash,
                                                         &ckey);
    }
    return (cdata);
}

static void
scsi_end_task (packet_info *pinfo)
{
    scsi_task_data_t *cdata = NULL;
    scsi_task_key_t ckey, *req_key;
    conversation_t *conversation;

    if ((pinfo != NULL) && (pinfo->private_data)) {
        ckey.conv_idx = (guint32)pinfo->private_data;
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
                                        sizeof(scsi_task_key_t),
                                        scsi_init_count *
                                        sizeof(scsi_task_key_t),
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
    scsi_task_key_t ckey, *req_key;
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
