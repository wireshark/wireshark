/* This dissector is based on the SBC2 specification.
 * TODO  
 * parts of opcodes 
 * 0x7f
 * 0xa3
 * 0xa4
 * 0x9e
 * are still missing. 
 * Some DATA IN/OUT PDUs are missing as well.
 */
/* packet-scsi-sbc.c
 * Dissector for the SCSI SBC commandset
 * Extracted from packet-scsi.c
 *
 * Dinesh G Dutt (ddutt@cisco.com)
 * Ronnie sahlberg 2006
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-sbc.h"


static int proto_scsi_sbc			= -1;
int hf_scsi_sbc_opcode				= -1;
static int hf_scsi_sbc_formatunit_flags		= -1;
static int hf_scsi_sbc_defect_list_format	= -1;
static int hf_scsi_sbc_formatunit_vendor	= -1;
static int hf_scsi_sbc_formatunit_interleave	= -1;
static int hf_scsi_sbc_rdwr6_lba		= -1;
static int hf_scsi_sbc_rdwr6_xferlen		= -1;
static int hf_scsi_sbc_rdwr10_lba		= -1;
static int hf_scsi_sbc_rdwr10_xferlen		= -1;
static int hf_scsi_sbc_rdwr12_xferlen		= -1;
static int hf_scsi_sbc_rdwr16_lba		= -1;
static int hf_scsi_sbc_ssu_immed_flags		= -1;
static int hf_scsi_sbc_ssu_immed		= -1;
static int hf_scsi_sbc_ssu_pwr_flags		= -1;
static int hf_scsi_sbc_ssu_pwr_cond		= -1;
static int hf_scsi_sbc_ssu_loej			= -1;
static int hf_scsi_sbc_ssu_start		= -1;
static int hf_scsi_sbc_bytchk			= -1;
static int hf_scsi_sbc_verify_reladdr		= -1;
static int hf_scsi_sbc_verify_lba		= -1;
static int hf_scsi_sbc_verify_lba64		= -1;
static int hf_scsi_sbc_verify_vlen		= -1;
static int hf_scsi_sbc_verify_vlen32		= -1;
static int hf_scsi_sbc_wrverify_lba		= -1;
static int hf_scsi_sbc_wrverify_xferlen		= -1;
static int hf_scsi_sbc_wrverify_lba64		= -1;
static int hf_scsi_sbc_wrverify_xferlen32	= -1;
static int hf_scsi_sbc_readcapacity_flags	= -1;
static int hf_scsi_sbc_readdefdata_flags	= -1;
static int hf_scsi_sbc_reassignblks_flags	= -1;
static int hf_scsi_sbc_read_flags		= -1;
static int hf_scsi_sbc_alloclen32		= -1;
static int hf_scsi_sbc_alloclen16		= -1;
static int hf_scsi_sbc_fuflags_fmtpinfo		= -1;
static int hf_scsi_sbc_fuflags_rto_req		= -1;
static int hf_scsi_sbc_fuflags_longlist		= -1;
static int hf_scsi_sbc_fuflags_fmtdata		= -1;
static int hf_scsi_sbc_fuflags_cmplist		= -1;
static int hf_scsi_sbc_prefetch_flags		= -1;
static int hf_scsi_sbc_prefetch_immed		= -1;
static int hf_scsi_sbc_group			= -1;
static int hf_scsi_sbc_rdprotect		= -1;
static int hf_scsi_sbc_dpo			= -1;
static int hf_scsi_sbc_fua			= -1;
static int hf_scsi_sbc_fua_nv			= -1;
static int hf_scsi_sbc_blocksize		= -1;
static int hf_scsi_sbc_returned_lba		= -1;
static int hf_scsi_sbc_req_plist		= -1;
static int hf_scsi_sbc_req_glist		= -1;
static int hf_scsi_sbc_corrct_flags		= -1;
static int hf_scsi_sbc_corrct			= -1;
static int hf_scsi_sbc_reassignblocks_longlba	= -1;
static int hf_scsi_sbc_reassignblocks_longlist	= -1;
static int hf_scsi_sbc_synccache_flags		= -1;
static int hf_scsi_sbc_synccache_immed		= -1;
static int hf_scsi_sbc_synccache_sync_nv	= -1;
static int hf_scsi_sbc_vrprotect		= -1;
static int hf_scsi_sbc_verify_flags		= -1;
static int hf_scsi_sbc_wrprotect		= -1;
static int hf_scsi_sbc_wrverify_flags		= -1;
static int hf_scsi_sbc_writesame_flags		= -1;
static int hf_scsi_sbc_anchor			= -1;
static int hf_scsi_sbc_unmap			= -1;
static int hf_scsi_sbc_pbdata			= -1;
static int hf_scsi_sbc_lbdata			= -1;
static int hf_scsi_sbc_xdread_flags		= -1;
static int hf_scsi_sbc_xorpinfo			= -1;
static int hf_scsi_sbc_disable_write		= -1;
static int hf_scsi_sbc_xdwrite_flags		= -1;
static int hf_scsi_sbc_xdwriteread_flags	= -1;
static int hf_scsi_sbc_xpwrite_flags		= -1;
static int hf_scsi_sbc_unmap_flags		= -1;
static int hf_scsi_sbc_unmap_anchor	       	= -1;
static int hf_scsi_sbc_unmap_data_length       	= -1;
static int hf_scsi_sbc_unmap_block_descriptor_data_length = -1;
static int hf_scsi_sbc_unmap_lba		= -1;
static int hf_scsi_sbc_unmap_num_blocks		= -1;
static int hf_scsi_sbc_ptype			= -1;
static int hf_scsi_sbc_prot_en			= -1;
static int hf_scsi_sbc_p_i_exponent		= -1;
static int hf_scsi_sbc_lbppbe			= -1;
static int hf_scsi_sbc_lbpme			= -1;
static int hf_scsi_sbc_lbprz			= -1;
static int hf_scsi_sbc_lalba			= -1;
static int hf_scsi_sbc_get_lba_status_lba	= -1;
static int hf_scsi_sbc_get_lba_status_data_length = -1;
static int hf_scsi_sbc_get_lba_status_num_blocks = -1;
static int hf_scsi_sbc_get_lba_status_provisioning_status = -1;

static gint ett_scsi_format_unit		= -1;
static gint ett_scsi_prefetch			= -1;
static gint ett_scsi_rdwr			= -1;
static gint ett_scsi_xdread			= -1;
static gint ett_scsi_xdwrite			= -1;
static gint ett_scsi_xdwriteread		= -1;
static gint ett_scsi_xpwrite			= -1;
static gint ett_scsi_defectdata			= -1;
static gint ett_scsi_corrct			= -1;
static gint ett_scsi_reassign_blocks		= -1;
static gint ett_scsi_ssu_immed			= -1;
static gint ett_scsi_ssu_pwr			= -1;
static gint ett_scsi_synccache			= -1;
static gint ett_scsi_verify			= -1;
static gint ett_scsi_wrverify			= -1;
static gint ett_scsi_writesame			= -1;
static gint ett_scsi_unmap			= -1;
static gint ett_scsi_unmap_block_descriptor	= -1;
static gint ett_scsi_lba_status_descriptor      = -1;


static const true_false_string dpo_tfs = {
    "Disable Page Out (don't cache this data)",
    "Disable page out is DISABLED (cache this data)"
};
static const true_false_string fua_tfs = {
    "Read from the medium, not cache",
    "Read from cache if possible"
};
static const true_false_string fua_nv_tfs = {
    "Read from volatile cache is NOT permitted",
    "Read from volatile or non-volatile cache permitted"
};
static const true_false_string pmi_tfs = {
    "PMI is SET",
    "Pmi is CLEAR"
};

static void
dissect_sbc_formatunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *fuflags_fields[] = {
	&hf_scsi_sbc_fuflags_fmtpinfo,
	&hf_scsi_sbc_fuflags_rto_req,
	&hf_scsi_sbc_fuflags_longlist,
	&hf_scsi_sbc_fuflags_fmtdata,
	&hf_scsi_sbc_fuflags_cmplist,
	&hf_scsi_sbc_defect_list_format,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_formatunit_flags,
            ett_scsi_format_unit, fuflags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_formatunit_vendor, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_formatunit_interleave, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    /* TODO : add dissection of DATA */
}

static void
dissect_sbc_read6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%06x, Len: %u)",
                             tvb_get_ntoh24 (tvb, offset),
                             tvb_get_guint8 (tvb, offset+3));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_lba, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_xferlen, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_write6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%06x, Len: %u)",
                             tvb_get_ntoh24 (tvb, offset),
                             tvb_get_guint8 (tvb, offset+3));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_lba, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_xferlen, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_prefetch10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *prefetch_fields[] = {
	&hf_scsi_sbc_prefetch_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_prefetch_flags,
            ett_scsi_prefetch, prefetch_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_synchronizecache10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *sync_fields[] = {
	&hf_scsi_sbc_synccache_sync_nv,
	&hf_scsi_sbc_synccache_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_synccache_flags,
            ett_scsi_synccache, sync_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_synchronizecache16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *sync_fields[] = {
	&hf_scsi_sbc_synccache_sync_nv,
	&hf_scsi_sbc_synccache_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_synccache_flags,
            ett_scsi_synccache, sync_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_prefetch16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *prefetch_fields[] = {
	&hf_scsi_sbc_prefetch_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_prefetch_flags,
            ett_scsi_prefetch, prefetch_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_sbc_read10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *rdwr10_fields[] = {
	&hf_scsi_sbc_rdprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_xdread10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *xdread10_fields[] = {
	&hf_scsi_sbc_xorpinfo,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_xdread_flags,
            ett_scsi_xdread, xdread10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_xdwrite10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *xdwrite10_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_disable_write,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_xdwrite_flags,
            ett_scsi_xdwrite, xdwrite10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_xdwriteread10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *xdwriteread10_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_disable_write,
	&hf_scsi_sbc_fua_nv,
	&hf_scsi_sbc_xorpinfo,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_xdwriteread_flags,
            ett_scsi_xdwriteread, xdwriteread10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_xpwrite10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *xpwrite10_fields[] = {
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	&hf_scsi_sbc_xorpinfo,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_xpwrite_flags,
            ett_scsi_xpwrite, xpwrite10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_sbc_write10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *rdwr10_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_sbc_read12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr12_fields[] = {
	&hf_scsi_sbc_rdprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+5));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr12_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}
void
dissect_sbc_write12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr12_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+5));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr12_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_read16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr16_fields[] = {
	&hf_scsi_sbc_rdprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}
static void
dissect_sbc_write16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr16_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_orwrite (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr16_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_comparenwrite (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rdwr16_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_fua,
	&hf_scsi_sbc_fua_nv,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_read_flags,
            ett_scsi_rdwr, rdwr16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static const value_string scsi_ssu_pwrcnd_val[] = {
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

static const value_string scsi_ptype_val[] = {
    {0x0, "Type 1 protection" },
    {0x1, "Type 2 protection" },
    {0x2, "Type 3 protection" },
    {0, NULL},
};

static const value_string scsi_provisioning_type_val[] = {
    {0x0, "The LBA is MAPPED" },
    {0x1, "The LBA is DEALLOCATED" },
    {0x2, "The LBA is ANCHORED" },
    {0, NULL},
};

void
dissect_sbc_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                            guint offset, gboolean isreq _U_, gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *ssu_fields[] = {
	&hf_scsi_sbc_ssu_immed,
	NULL
    };
    static const int *pwr_fields[] = {
	&hf_scsi_sbc_ssu_pwr_cond,
	&hf_scsi_sbc_ssu_loej,
	&hf_scsi_sbc_ssu_start,
	NULL
    };

    if (!tree || !iscdb)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_ssu_immed_flags,
            ett_scsi_ssu_immed, ssu_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+3, hf_scsi_sbc_ssu_pwr_flags,
            ett_scsi_ssu_pwr, pwr_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_verify10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *verify10_fields[] = {
	&hf_scsi_sbc_vrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_verify_flags,
            ett_scsi_verify, verify10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_verify12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *verify12_fields[] = {
	&hf_scsi_sbc_vrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+5));
    }

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_verify_flags,
            ett_scsi_verify, verify12_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen32, tvb, offset+5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_verify16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    static const int *verify16_fields[] = {
	&hf_scsi_sbc_vrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_verify_flags,
            ett_scsi_verify, verify16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_lba64, tvb, offset+1, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen32, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}


static void
dissect_sbc_wrverify10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)

{
    static const int *wrverify10_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohs (tvb, offset+6));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_wrverify_flags,
        ett_scsi_wrverify, wrverify10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_wrverify12 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)
{
    static const int *wrverify12_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: 0x%08x, Len: %u)",
                             tvb_get_ntohl (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+5));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_wrverify_flags,
            ett_scsi_wrverify, wrverify12_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen32, tvb, offset+5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_wrverify16 (tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, guint offset, gboolean isreq,
                         gboolean iscdb, guint payload_len _U_,
                         scsi_task_data_t *cdata _U_)
{
    static const int *wrverify16_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_dpo,
	&hf_scsi_sbc_bytchk,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" G_GINT64_MODIFIER "u, Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_wrverify_flags,
            ett_scsi_wrverify, wrverify16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba64, tvb, offset+1, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen32, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

void
dissect_sbc_readcapacity10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint32 len, block_len, tot_len;
    const char *un;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
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
        proto_tree_add_uint_format (tree, hf_scsi_sbc_returned_lba, tvb, offset, 4, len, "LBA: %u (%u %s)", len, tot_len, un);
        proto_tree_add_item (tree, hf_scsi_sbc_blocksize, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_readdefectdata10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *defect_fields[] = {
	&hf_scsi_sbc_defect_list_format,
	&hf_scsi_sbc_req_plist,
	&hf_scsi_sbc_req_glist,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_sbc_readdefdata_flags,
            ett_scsi_defectdata, defect_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    /* TODO : add dissection of DATA */
}


static void
dissect_sbc_readlong10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *corrct_fields[] = {
	&hf_scsi_sbc_corrct,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_corrct_flags,
            ett_scsi_corrct, corrct_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_writelong10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_writesame10 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *writesame10_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_anchor,
	&hf_scsi_sbc_unmap,
	&hf_scsi_sbc_pbdata,
	&hf_scsi_sbc_lbdata,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_writesame_flags,
            ett_scsi_writesame, writesame10_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_writesame16 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *writesame16_fields[] = {
	&hf_scsi_sbc_wrprotect,
	&hf_scsi_sbc_anchor,
	&hf_scsi_sbc_unmap,
	&hf_scsi_sbc_pbdata,
	&hf_scsi_sbc_lbdata,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_writesame_flags,
            ett_scsi_writesame, writesame16_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, ENC_NA);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_sbc_unmap (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *unmap_fields[] = {
	&hf_scsi_sbc_unmap_anchor,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_unmap_flags,
            ett_scsi_unmap, unmap_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_group, tvb, offset+5, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    } else if (isreq) {
        proto_tree_add_item (tree, hf_scsi_sbc_unmap_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_unmap_block_descriptor_data_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
	offset += 8;
	while (tvb_reported_length_remaining(tvb, offset) >=16) {
	    proto_tree *tr;
	    proto_item *it;
	    gint64 lba;
	    gint32 num_blocks;

	    it = proto_tree_add_text(tree, tvb, offset, 16, "UNMAP Block Descriptor: LBA ");
	    tr = proto_item_add_subtree(it, ett_scsi_unmap_block_descriptor);

	    proto_tree_add_item (tr, hf_scsi_sbc_unmap_lba, tvb, offset, 8, ENC_BIG_ENDIAN);
	    lba = tvb_get_ntoh64 (tvb, offset);

	    proto_tree_add_item (tr, hf_scsi_sbc_unmap_num_blocks, tvb, offset+8, 4, ENC_BIG_ENDIAN);
	    num_blocks = tvb_get_ntohl(tvb, offset+8);

	    if (num_blocks > 1) {
                proto_item_append_text (it, "%" G_GINT64_MODIFIER "u-%" G_GINT64_MODIFIER "u  ", lba, lba+num_blocks-1);
	    } else {
                proto_item_append_text (it, "%" G_GINT64_MODIFIER "u  ", lba);
	    }

	    offset += 16;
	}
    }
}

static void
dissect_sbc_readdefectdata12 (tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, guint offset, gboolean isreq,
                            gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *defect_fields[] = {
	&hf_scsi_sbc_defect_list_format,
	&hf_scsi_sbc_req_plist,
	&hf_scsi_sbc_req_glist,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_readdefdata_flags,
            ett_scsi_defectdata, defect_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen32, tvb, offset+5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    /* TODO : add dissection of DATA */
}


static void
dissect_sbc_reassignblocks (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, gboolean isreq,
                           gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *reassign_fields[] = {
	&hf_scsi_sbc_reassignblocks_longlba,
	&hf_scsi_sbc_reassignblocks_longlist,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_reassignblks_flags,
            ett_scsi_reassign_blocks, reassign_fields, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    /* TODO : add dissection of DATA */
}


const value_string service_action_vals[] = {
	{SHORT_FORM_BLOCK_ID,        "Short Form - Block ID"},
	{SHORT_FORM_VENDOR_SPECIFIC, "Short Form - Vendor-Specific"},
	{LONG_FORM,                  "Long Form"},
	{EXTENDED_FORM,              "Extended Form"},
	{SERVICE_READ_CAPACITY16,    "Read Capacity(16)"},
	{SERVICE_READ_LONG16,	     "Read Long(16)"},
	{SERVICE_GET_LBA_STATUS,     "Get LBA Status"},
	{0, NULL}
};

/* this is either readcapacity16  or  readlong16  depending of what service
   action is set to.
*/
static void
dissect_sbc_serviceactionin16 (tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, guint offset, gboolean isreq,
                           gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 service_action;
    guint32 block_len;
    guint64 len, tot_len;
    const char *un;

    if (!tree)
        return;

    if (isreq && iscdb) {
        service_action = tvb_get_guint8 (tvb, offset) & 0x1F;
        if(cdata && cdata->itlq){
            cdata->itlq->flags=service_action;
        }

	switch(service_action){
	case SERVICE_READ_CAPACITY16:
	        col_append_str(pinfo->cinfo, COL_INFO, " READCAPACITY16");

        	proto_tree_add_text (tree, tvb, offset, 1,
                             "Service Action: %s",
                             val_to_str (service_action,
                                         service_action_vals,
                                         "Unknown (0x%02x)"));
        	offset += 9;

	        proto_tree_add_item (tree, hf_scsi_sbc_alloclen32, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 5;

		proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
			ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
		offset++;

		break;
	case SERVICE_READ_LONG16:
	        col_append_str(pinfo->cinfo, COL_INFO, " READ_LONG16");
        	proto_tree_add_text (tree, tvb, offset, 1,
                             "Service Action: %s",
                             val_to_str (service_action,
                                         service_action_vals,
                                         "Unknown (0x%02x)"));
		offset++;

        	proto_tree_add_text (tree, tvb, offset, 8,
                             "Logical Block Address: %" G_GINT64_MODIFIER "u",
                              tvb_get_ntoh64 (tvb, offset));
        	offset+=8;

		/* two reserved bytes */
		offset+=2;

		proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		/* CORRCT bit */
		offset++;

		proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
			ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
		offset++;

		break;
	case SERVICE_GET_LBA_STATUS:
	        col_append_str(pinfo->cinfo, COL_INFO, " GET_LBA_STATUS");

        	proto_tree_add_text (tree, tvb, offset, 1,
                             "Service Action: %s",
                             val_to_str (service_action,
                                         service_action_vals,
                                         "Unknown (0x%02x)"));
		offset++;

		proto_tree_add_item (tree, hf_scsi_sbc_get_lba_status_lba, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;

	        proto_tree_add_item (tree, hf_scsi_sbc_alloclen32, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* reserved */
		offset++;

		proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
			ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
		offset++;

		break;
	};
    } else if (!iscdb) {
        if(cdata && cdata->itlq){
            switch(cdata->itlq->flags){
            case SERVICE_READ_CAPACITY16:
                len = tvb_get_ntoh64 (tvb, offset);
                block_len = tvb_get_ntohl (tvb, offset+8);
                tot_len=((len/1024)*block_len)/1024; /*MB*/
                un="MB";
                if(tot_len>20000){
                    tot_len/=1024;
                    un="GB";
                }
                proto_tree_add_text (tree, tvb, offset, 8, "LBA: %" G_GINT64_MODIFIER "u (%" G_GINT64_MODIFIER "u %s)",
                             len, tot_len, un);
                proto_tree_add_item (tree, hf_scsi_sbc_blocksize, tvb, offset+8, 4, ENC_BIG_ENDIAN);


                proto_tree_add_item (tree, hf_scsi_sbc_prot_en, tvb, offset+12, 1, ENC_BIG_ENDIAN);
		if (tvb_get_guint8(tvb, offset+12) & 0x01) {
			/* only decode the protection type if protection is enabled */
        	        proto_tree_add_item (tree, hf_scsi_sbc_ptype, tvb, offset+12, 1, ENC_BIG_ENDIAN);
		}

                proto_tree_add_item (tree, hf_scsi_sbc_p_i_exponent, tvb, offset+13, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_sbc_lbppbe, tvb, offset+13, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item (tree, hf_scsi_sbc_lbpme, tvb, offset+14, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_sbc_lbprz, tvb, offset+14, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_sbc_lalba, tvb, offset+14, 2, ENC_BIG_ENDIAN);

                break;
	    case SERVICE_GET_LBA_STATUS:
		proto_tree_add_item (tree, hf_scsi_sbc_get_lba_status_data_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                block_len = tvb_get_ntohl (tvb, offset);
		offset += 4;

		/* reserved */
		offset += 4;

		while (tvb_length_remaining(tvb, offset) >= 16) {
			proto_tree *tr;
			proto_item *it;
			guint64 lba;
			guint32 num_blocks;
			guint8  type;

			it = proto_tree_add_text(tree, tvb, offset, 16, "LBA Status Descriptor:  ");
			tr = proto_item_add_subtree(it, ett_scsi_lba_status_descriptor);

			proto_tree_add_item (tr, hf_scsi_sbc_get_lba_status_lba, tvb, offset, 8, ENC_BIG_ENDIAN);
			lba = tvb_get_ntoh64(tvb, offset);
			offset += 8;

			proto_tree_add_item (tr, hf_scsi_sbc_get_lba_status_num_blocks, tvb, offset, 4, ENC_BIG_ENDIAN);
			num_blocks = tvb_get_ntohl(tvb, offset);
			offset += 4;

			proto_tree_add_item (tr, hf_scsi_sbc_get_lba_status_provisioning_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			type = tvb_get_guint8(tvb, offset) & 0x07;
			offset++;

			/* reserved */
			offset += 3;

			proto_item_append_text (it, "%" G_GINT64_MODIFIER "u-%" G_GINT64_MODIFIER "u  %s",
				lba,
				lba + num_blocks - 1,
				val_to_str(type, scsi_provisioning_type_val, "Unknown (0x%02x)")
				);
		}
	        break;
            }
        }
    }
}


/* SBC Commands */
const value_string scsi_sbc_vals[] = {
    {SCSI_SPC_EXTCOPY           , "Extended Copy"},
    {SCSI_SPC_INQUIRY           , "Inquiry"},
    {SCSI_SBC_FORMATUNIT        , "Format Unit"},
    {SCSI_SBC_LOCKUNLKCACHE10   , "Lock Unlock Cache(10)"},
    {SCSI_SBC_LOCKUNLKCACHE16   , "Lock Unlock Cache(16)"},
    {SCSI_SPC_LOGSELECT         , "Log Select"},
    {SCSI_SPC_LOGSENSE          , "Log Sense"},
    {SCSI_SPC_MODESELECT6       , "Mode Select(6)"},
    {SCSI_SPC_MODESELECT10      , "Mode Select(10)"},
    {SCSI_SPC_MODESENSE6        , "Mode Sense(6)"},
    {SCSI_SPC_MODESENSE10       , "Mode Sense(10)"},
    {SCSI_SPC_PERSRESVIN        , "Persistent Reserve In"},
    {SCSI_SPC_PERSRESVOUT       , "Persistent Reserve Out"},
    {SCSI_SBC_PREFETCH10        , "Pre-Fetch(10)"},
    {SCSI_SBC_PREFETCH16        , "Pre-Fetch(16)"},
    {SCSI_SPC_PREVMEDREMOVAL    , "Prevent/Allow Medium Removal"},
    {SCSI_SBC_READ6             , "Read(6)"},
    {SCSI_SBC_READ10            , "Read(10)"},
    {SCSI_SBC_READ12            , "Read(12)"},
    {SCSI_SBC_READ16            , "Read(16)"},
    {SCSI_SBC_READCAPACITY10    , "Read Capacity(10)"},
    {SCSI_SPC_REPORTLUNS        , "Report LUNs"},
    {SCSI_SPC_REQSENSE          , "Request Sense"},
    {SCSI_SBC_SERVICEACTIONIN16 , "Service Action In(16)"},
    {SCSI_SBC_READDEFDATA10     , "Read Defect Data(10)"},
    {SCSI_SBC_READDEFDATA12     , "Read Defect Data(12)"},
    {SCSI_SBC_READLONG          , "Read Long(10)"},
    {SCSI_SBC_REASSIGNBLKS      , "Reassign Blocks"},
    {SCSI_SBC_REBUILD16         , "Rebuild(16)"},
    {SCSI_SBC_REBUILD32         , "Rebuild(32)"},
    {SCSI_SBC_REGENERATE16      , "Regenerate(16)"},
    {SCSI_SBC_REGENERATE32      , "Regenerate(32)"},
    {SCSI_SPC_RELEASE6          , "Release(6)"}, /* obsolete in SBC2 and later */
    {SCSI_SPC_RELEASE10         , "Release(10)"},/* obsolete in SBC2 and later */
    {SCSI_SPC_RESERVE6          , "Reserve(6)"}, /* obsolete in SBC2 and later */
    {SCSI_SPC_RESERVE10         , "Reserve(10)"},/* obsolete in SBC2 and later */
    {SCSI_SBC_SEEK10            , "Seek(10)"},
    {SCSI_SPC_SENDDIAG          , "Send Diagnostic"},
    {SCSI_SBC_SETLIMITS10       , "Set Limits(10)"},
    {SCSI_SBC_SETLIMITS12       , "Set Limits(12)"},
    {SCSI_SBC_STARTSTOPUNIT     , "Start Stop Unit"},
    {SCSI_SBC_SYNCCACHE10       , "Synchronize Cache(10)"},
    {SCSI_SBC_SYNCCACHE16       , "Synchronize Cache(16)"},
    {SCSI_SPC_TESTUNITRDY       , "Test Unit Ready"},
    {SCSI_SBC_UNMAP             , "Unmap"},
    {SCSI_SBC_VERIFY10          , "Verify(10)"},
    {SCSI_SBC_VERIFY12          , "Verify(12)"},
    {SCSI_SBC_VERIFY16          , "Verify(16)"},
    {SCSI_SBC_WRITE6            , "Write(6)"},
    {SCSI_SBC_WRITE10           , "Write(10)"},
    {SCSI_SBC_WRITE12           , "Write(12)"},
    {SCSI_SBC_WRITE16           , "Write(16)"},
    {SCSI_SBC_ORWRITE           , "OrWrite(16)"},
    {SCSI_SPC_WRITEBUFFER       , "Write Buffer"},
    {SCSI_SBC_COMPARENWRITE     , "Compare & Write(16)"},
    {SCSI_SBC_WRITENVERIFY10    , "Write & Verify(10)"},
    {SCSI_SBC_WRITENVERIFY12    , "Write & Verify(12)"},
    {SCSI_SBC_WRITENVERIFY16    , "Write & Verify(16)"},
    {SCSI_SBC_WRITELONG         , "Write Long"},
    {SCSI_SBC_WRITESAME10       , "Write Same(10)"},
    {SCSI_SBC_WRITESAME16       , "Write Same(16)"},
    {SCSI_SBC_XDREAD10          , "XdRead(10)"},
    {SCSI_SBC_XDREAD32          , "XdRead(32)"},
    {SCSI_SBC_XDWRITE10         , "XdWrite(10)"},
    {SCSI_SBC_XDWRITE32         , "XdWrite(32)"},
    {SCSI_SBC_XDWRITEREAD10     , "XdWriteRead(10)"},
    {SCSI_SBC_XDWRITEREAD32     , "XdWriteRead(32)"},
    {SCSI_SBC_XDWRITEEXTD16     , "XdWrite Extended(16)"},
    {SCSI_SBC_XDWRITEEXTD32     , "XdWrite Extended(32)"},
    {SCSI_SBC_XPWRITE10         , "XpWrite(10)"},
    {SCSI_SBC_XPWRITE32         , "XpWrite(32)"},
    {0, NULL}
};

scsi_cdb_table_t scsi_sbc_table[256] = {
/*SPC 0x00*/{dissect_spc_testunitready},
/*SBC 0x01*/{NULL},
/*SBC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc_requestsense},
/*SBC 0x04*/{dissect_sbc_formatunit},
/*SBC 0x05*/{NULL},
/*SBC 0x06*/{NULL},
/*SBC 0x07*/{dissect_sbc_reassignblocks},
/*SBC 0x08*/{dissect_sbc_read6},
/*SBC 0x09*/{NULL},
/*SBC 0x0a*/{dissect_sbc_write6},
/*SBC 0x0b*/{NULL},
/*SBC 0x0c*/{NULL},
/*SBC 0x0d*/{NULL},
/*SBC 0x0e*/{NULL},
/*SBC 0x0f*/{NULL},
/*SBC 0x10*/{NULL},
/*SBC 0x11*/{NULL},
/*SPC 0x12*/{dissect_spc_inquiry},
/*SBC 0x13*/{NULL},
/*SBC 0x14*/{NULL},
/*SPC 0x15*/{dissect_spc_modeselect6},
/*SBC 0x16*/{dissect_spc_reserve6}, /* obsolete in SBC2 and later */
/*SBC 0x17*/{dissect_spc_release6}, /* obsolete in SBC2 and later */
/*SBC 0x18*/{NULL},
/*SBC 0x19*/{NULL},
/*SPC 0x1a*/{dissect_spc_modesense6},
/*SBC 0x1b*/{dissect_sbc_startstopunit},
/*SBC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc_senddiagnostic},
/*SBC 0x1e*/{dissect_spc_preventallowmediaremoval},
/*SBC 0x1f*/{NULL},
/*SBC 0x20*/{NULL},
/*SBC 0x21*/{NULL},
/*SBC 0x22*/{NULL},
/*SBC 0x23*/{NULL},
/*SBC 0x24*/{NULL},
/*SBC 0x25*/{dissect_sbc_readcapacity10},
/*SBC 0x26*/{NULL},
/*SBC 0x27*/{NULL},
/*SBC 0x28*/{dissect_sbc_read10},
/*SBC 0x29*/{NULL},
/*SBC 0x2a*/{dissect_sbc_write10},
/*SBC 0x2b*/{NULL},
/*SBC 0x2c*/{NULL},
/*SBC 0x2d*/{NULL},
/*SBC 0x2e*/{dissect_sbc_wrverify10},
/*SBC 0x2f*/{dissect_sbc_verify10},
/*SBC 0x30*/{NULL},
/*SBC 0x31*/{NULL},
/*SBC 0x32*/{NULL},
/*SBC 0x33*/{NULL},
/*SBC 0x34*/{dissect_sbc_prefetch10},
/*SBC 0x35*/{dissect_sbc_synchronizecache10},
/*SBC 0x36*/{NULL},
/*SBC 0x37*/{dissect_sbc_readdefectdata10},
/*SBC 0x38*/{NULL},
/*SBC 0x39*/{NULL},
/*SBC 0x3a*/{NULL},
/*SPC 0x3b*/{dissect_spc_writebuffer},
/*SBC 0x3c*/{NULL},
/*SBC 0x3d*/{NULL},
/*SBC 0x3e*/{dissect_sbc_readlong10},
/*SBC 0x3f*/{dissect_sbc_writelong10},
/*SBC 0x40*/{NULL},
/*SBC 0x41*/{dissect_sbc_writesame10},
/*SBC 0x42*/{dissect_sbc_unmap}, 
/*SBC 0x43*/{NULL},
/*SBC 0x44*/{NULL},
/*SBC 0x45*/{NULL},
/*SBC 0x46*/{NULL},
/*SBC 0x47*/{NULL},
/*SBC 0x48*/{NULL},
/*SBC 0x49*/{NULL},
/*SBC 0x4a*/{NULL},
/*SBC 0x4b*/{NULL},
/*SPC 0x4c*/{dissect_spc_logselect},
/*SPC 0x4d*/{dissect_spc_logsense},
/*SBC 0x4e*/{NULL},
/*SBC 0x4f*/{NULL},
/*SBC 0x50*/{dissect_sbc_xdwrite10},
/*SBC 0x51*/{dissect_sbc_xpwrite10},
/*SBC 0x52*/{dissect_sbc_xdread10},
/*SBC 0x53*/{dissect_sbc_xdwriteread10},
/*SBC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc_modeselect10},
/*SPC 0x56*/{dissect_spc_reserve10},/* obsolete in SBC2 and later */
/*SPC 0x57*/{dissect_spc_release10},/* obsolete in SBC2 and later */
/*SBC 0x58*/{NULL},
/*SBC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc_modesense10},
/*SBC 0x5b*/{NULL},
/*SBC 0x5c*/{NULL},
/*SBC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc_persistentreservein},
/*SPC 0x5f*/{dissect_spc_persistentreserveout},
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
/*SPC 0x83*/{dissect_spc_extcopy},
/*SBC 0x84*/{NULL},
/*SBC 0x85*/{NULL},
/*SBC 0x86*/{NULL},
/*SBC 0x87*/{NULL},
/*SBC 0x88*/{dissect_sbc_read16},
/*SBC 0x89*/{dissect_sbc_comparenwrite},
/*SBC 0x8a*/{dissect_sbc_write16},
/*SBC 0x8b*/{dissect_sbc_orwrite},
/*SBC 0x8c*/{NULL},
/*SBC 0x8d*/{NULL},
/*SBC 0x8e*/{dissect_sbc_wrverify16},
/*SBC 0x8f*/{dissect_sbc_verify16},
/*SBC 0x90*/{dissect_sbc_prefetch16},
/*SBC 0x91*/{dissect_sbc_synchronizecache16},
/*SBC 0x92*/{NULL},
/*SBC 0x93*/{dissect_sbc_writesame16},
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
/*SBC 0x9e*/{dissect_sbc_serviceactionin16},
/*SBC 0x9f*/{NULL},
/*SPC 0xa0*/{dissect_spc_reportluns},
/*SBC 0xa1*/{NULL},
/*SBC 0xa2*/{NULL},
/*SBC 0xa3*/{NULL},
/*SBC 0xa4*/{NULL},
/*SBC 0xa5*/{NULL},
/*SBC 0xa6*/{NULL},
/*SBC 0xa7*/{NULL},
/*SBC 0xa8*/{dissect_sbc_read12},
/*SBC 0xa9*/{NULL},
/*SBC 0xaa*/{dissect_sbc_write12},
/*SBC 0xab*/{NULL},
/*SBC 0xac*/{NULL},
/*SBC 0xad*/{NULL},
/*SBC 0xae*/{dissect_sbc_wrverify12},
/*SBC 0xaf*/{dissect_sbc_verify12},
/*SBC 0xb0*/{NULL},
/*SBC 0xb1*/{NULL},
/*SBC 0xb2*/{NULL},
/*SBC 0xb3*/{NULL},
/*SBC 0xb4*/{NULL},
/*SBC 0xb5*/{NULL},
/*SBC 0xb6*/{NULL},
/*SBC 0xb7*/{dissect_sbc_readdefectdata12},
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


void
proto_register_scsi_sbc(void)
{
	static hf_register_info hf[] = {
        { &hf_scsi_sbc_opcode,
          {"SBC Opcode", "scsi_sbc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_formatunit_flags,
          {"Flags", "scsi_sbc.formatunit.flags", FT_UINT8, BASE_HEX, NULL, 0xF8,
           NULL, HFILL}},
        { &hf_scsi_sbc_defect_list_format,
          {"Defect List Format", "scsi_sbc.defect_list_format", FT_UINT8, BASE_DEC,
           NULL, 0x7, NULL, HFILL}},
        { &hf_scsi_sbc_formatunit_vendor,
          {"Vendor Unique", "scsi_sbc.formatunit.vendor", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_sbc_formatunit_interleave,
          {"Interleave", "scsi_sbc.formatunit.interleave", FT_UINT16, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_rdwr6_lba,
          {"Logical Block Address (LBA)", "scsi_sbc.rdwr6.lba", FT_UINT24, BASE_DEC,
           NULL, 0x0FFFFF, NULL, HFILL}},
        { &hf_scsi_sbc_rdwr6_xferlen,
          {"Transfer Length", "scsi_sbc.rdwr6.xferlen", FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_sbc_rdwr10_lba,
          {"Logical Block Address (LBA)", "scsi_sbc.rdwr10.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_rdwr10_xferlen,
          {"Transfer Length", "scsi_sbc.rdwr10.xferlen", FT_UINT16, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_sbc_rdwr12_xferlen,
          {"Transfer Length", "scsi_sbc.rdwr12.xferlen", FT_UINT32, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_sbc_rdwr16_lba,
          {"Logical Block Address (LBA)", "scsi_sbc.rdwr16.lba", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_ssu_immed,
          {"Immediate", "scsi_sbc.ssu.immediate", FT_BOOLEAN, 8, NULL,
           0x01, NULL, HFILL}},
        { &hf_scsi_sbc_ssu_pwr_cond,
          {"Power Conditions", "scsi_sbc.ssu.pwr", FT_UINT8, BASE_HEX,
           VALS (scsi_ssu_pwrcnd_val), 0xF0, NULL, HFILL}},
        { &hf_scsi_sbc_ssu_loej,
          {"LOEJ", "scsi_sbc.ssu.loej", FT_BOOLEAN, 8, NULL, 0x2, NULL,
           HFILL}},
        { &hf_scsi_sbc_ssu_start,
          {"Start", "scsi_sbc.ssu.start", FT_BOOLEAN, 8, NULL, 0x1,
           NULL, HFILL}},
        { &hf_scsi_sbc_bytchk,
          {"BYTCHK", "scsi_sbc.bytchk", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_sbc_verify_reladdr,
          {"RELADDR", "scsi_sbc.verify.reladdr", FT_BOOLEAN, 8, NULL,
           0x1, NULL, HFILL}},
        { &hf_scsi_sbc_verify_lba,
          {"LBA", "scsi_sbc.verify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_verify_lba64,
          {"LBA", "scsi_sbc.verify.lba64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_verify_vlen,
          {"Verification Length", "scsi_sbc.verify.vlen", FT_UINT16,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_verify_vlen32,
          {"Verification Length", "scsi_sbc.verify.vlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_wrverify_lba,
          {"LBA", "scsi_sbc.wrverify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_wrverify_xferlen,
          {"Transfer Length", "scsi_sbc.wrverify.xferlen", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_wrverify_lba64,
          {"LBA", "scsi_sbc.wrverify.lba64", FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_sbc_wrverify_xferlen32,
          {"Transfer Length", "scsi_sbc.wrverify.xferlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_readcapacity_flags,
          {"Flags", "scsi_sbc.readcapacity.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_sbc_readdefdata_flags,
          {"Flags", "scsi_sbc.readdefdata.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_reassignblks_flags,
          {"Flags", "scsi_sbc.reassignblks.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_read_flags,
          {"Flags", "scsi_sbc.read.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_alloclen32,
          {"Allocation Length", "scsi_sbc.alloclen32", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_alloclen16,
          {"Allocation Length", "scsi_sbc.alloclen16", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_sbc_fuflags_fmtpinfo,
          {"FMTPINFO", "scsi_sbc.format_unit.fmtpinfo", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_sbc_fuflags_rto_req,
          {"RTO_REQ", "scsi_sbc.format_unit.rto_req", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_sbc_fuflags_longlist,
          {"LONGLIST", "scsi_sbc.format_unit.longlist", FT_BOOLEAN, 8,
           NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_sbc_fuflags_fmtdata,
          {"FMTDATA", "scsi_sbc.format_unit.fmtdata", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_sbc_fuflags_cmplist,
          {"CMPLIST", "scsi_sbc.format_unit.cmplist", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_sbc_prefetch_flags,
          {"Flags", "scsi_sbc.prefetch.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_prefetch_immed,
          {"Immediate", "scsi_sbc.prefetch.immediate", FT_BOOLEAN, 8, NULL,
           0x2, NULL, HFILL}},
        { &hf_scsi_sbc_group,
          {"Group", "scsi_sbc.group", FT_UINT8, BASE_HEX, NULL,
           0x1f, NULL, HFILL}},
        { &hf_scsi_sbc_rdprotect,
          {"RDPROTECT", "scsi_sbc.rdprotect", FT_UINT8, BASE_HEX,
           NULL, 0xe0, NULL, HFILL}},
        { &hf_scsi_sbc_dpo,
          {"DPO", "scsi_sbc.dpo", FT_BOOLEAN, 8,
           TFS(&dpo_tfs), 0x10, "DisablePageOut: Whether the device should cache the data or not", HFILL}},
        { &hf_scsi_sbc_fua,
          {"FUA", "scsi_sbc.fua", FT_BOOLEAN, 8,
           TFS(&fua_tfs), 0x08, "ForceUnitAccess: Whether to allow reading from the cache or not", HFILL}},
        { &hf_scsi_sbc_fua_nv,
          {"FUA_NV", "scsi_sbc.fua_nv", FT_BOOLEAN, 8,
           TFS(&fua_nv_tfs), 0x02, "ForceUnitAccess_NonVolatile: Whether to allow reading from non-volatile cache or not", HFILL}},
        { &hf_scsi_sbc_blocksize,
          {"Block size in bytes", "scsi_sbc.blocksize", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_returned_lba,
          {"Returned LBA", "scsi_sbc.returned_lba", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_req_plist,
          {"REQ_PLIST", "scsi_sbc.req_plist", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_sbc_req_glist,
          {"REQ_GLIST", "scsi_sbc.req_glist", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_sbc_corrct,
          {"CORRCT", "scsi_sbc.corrct", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_sbc_corrct_flags,
          {"Flags", "scsi_sbc.corrct_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_reassignblocks_longlba,
          {"LongLBA", "scsi_sbc.reassignblocks.longlba", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_sbc_reassignblocks_longlist,
          {"LongList", "scsi_sbc.reassignblocks.longlist", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_sbc_ssu_immed_flags,
          {"Immed flags", "scsi_sbc.ssu.immed_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_ssu_pwr_flags,
          {"Pwr flags", "scsi_sbc.ssu.pwr_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_synccache_flags,
          {"Flags", "scsi_sbc.synccache.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_synccache_immed,
          {"Immediate", "scsi_sbc.synccache.immediate", FT_BOOLEAN, 8, NULL,
           0x02, NULL, HFILL}},
        { &hf_scsi_sbc_synccache_sync_nv,
          {"SYNC_NV", "scsi_sbc.synccache.sync_nv", FT_BOOLEAN, 8, NULL,
           0x04, NULL, HFILL}},
        { &hf_scsi_sbc_vrprotect,
          {"VRPROTECT", "scsi_sbc.vrprotect", FT_UINT8, BASE_HEX,
           NULL, 0xe0, NULL, HFILL}},
        { &hf_scsi_sbc_verify_flags,
          {"Flags", "scsi_sbc.verify_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_wrprotect,
          {"WRPROTECT", "scsi_sbc.wrprotect", FT_UINT8, BASE_HEX,
           NULL, 0xe0, NULL, HFILL}},
        { &hf_scsi_sbc_wrverify_flags,
          {"Flags", "scsi_sbc.wrverify_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_writesame_flags,
          {"Flags", "scsi_sbc.writesame_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_anchor,
          {"ANCHOR", "scsi_sbc.anchor", FT_BOOLEAN, 8, NULL,
           0x10, NULL, HFILL}},
        { &hf_scsi_sbc_unmap,
          {"UNMAP", "scsi_sbc.unmap", FT_BOOLEAN, 8, NULL,
           0x08, NULL, HFILL}},
        { &hf_scsi_sbc_pbdata,
          {"PBDATA", "scsi_sbc.pbdata", FT_BOOLEAN, 8, NULL,
           0x04, NULL, HFILL}},
        { &hf_scsi_sbc_lbdata,
          {"LBDATA", "scsi_sbc.lbdata", FT_BOOLEAN, 8, NULL,
           0x02, NULL, HFILL}},
        { &hf_scsi_sbc_xdread_flags,
          {"Flags", "scsi_sbc.xdread.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_xorpinfo,
          {"XORPINFO", "scsi_sbc.xorpinfo", FT_BOOLEAN, 8, NULL,
           0x01, NULL, HFILL}},
        { &hf_scsi_sbc_disable_write,
          {"DISABLE_WRITE", "scsi_sbc.disable_write", FT_BOOLEAN, 8, NULL,
           0x04, NULL, HFILL}},
        { &hf_scsi_sbc_xdwrite_flags,
          {"Flags", "scsi_sbc.xdwrite.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_xdwriteread_flags,
          {"Flags", "scsi_sbc.xdwriteread.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_xpwrite_flags,
          {"Flags", "scsi_sbc.xpwrite.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_scsi_sbc_unmap_anchor,
          {"ANCHOR", "scsi_sbc.unmap.anchor", FT_BOOLEAN, 8, NULL,
           0x01, NULL, HFILL}},
        { &hf_scsi_sbc_unmap_flags,
          {"Flags", "scsi_sbc.unmap_flags", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_unmap_data_length,
          {"Data Length", "scsi_sbc.unmap.data_length", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_unmap_block_descriptor_data_length,
          {"Block Descriptor Data Length", "scsi_sbc.unmap.block_descriptor_data_length", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_unmap_lba,
          {"LBA", "scsi_sbc.unmap.lba", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_unmap_num_blocks,
          {"Num Blocks", "scsi_sbc.unmap.num_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_ptype,
          {"PTYPE", "scsi_sbc.ptype", FT_UINT8, BASE_DEC,
           VALS(scsi_ptype_val), 0x0e, NULL, HFILL}},
        { &hf_scsi_sbc_prot_en,
          {"PROT_EN", "scsi_sbc.prot_en", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_sbc_p_i_exponent,
          {"P_I_EXPONENT", "scsi_sbc.p_i_exponent", FT_UINT8, BASE_DEC,
           NULL, 0xf0, NULL, HFILL}},
        { &hf_scsi_sbc_lbppbe,
          {"LOGICAL_BLOCKS_PER_PHYSICAL_BLOCK_EXPONENT", "scsi_sbc.lbppbe", FT_UINT8, BASE_DEC,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_sbc_lbpme,
          {"LBPME", "scsi_sbc.lbpme", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_sbc_lbprz,
          {"LBPRZ", "scsi_sbc.lbprz", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_sbc_lalba,
          {"LOWEST_ALIGNED_LBA", "scsi_sbc.lalba", FT_UINT16, BASE_DEC,
           NULL, 0x3fff, NULL, HFILL}},
        { &hf_scsi_sbc_get_lba_status_lba,
          {"LBA", "scsi_sbc.get_lba_status.start_lba", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_get_lba_status_data_length,
          {"Data Length", "scsi_sbc.get_lba_status.data_length", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_sbc_get_lba_status_num_blocks,
          {"Num Blocks", "scsi_sbc.get_lba_status.num_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
	{ &hf_scsi_sbc_get_lba_status_provisioning_status,
          {"Provisioning Type", "scsi_sbc.get_lba_status.provisioning_type", FT_UINT8, BASE_DEC,
           VALS(scsi_provisioning_type_val), 0x07, NULL, HFILL}},
	};


	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_scsi_format_unit,
		&ett_scsi_prefetch,
		&ett_scsi_rdwr,
		&ett_scsi_xdread,
		&ett_scsi_xdwrite,
		&ett_scsi_xdwriteread,
		&ett_scsi_xpwrite,
		&ett_scsi_defectdata,
		&ett_scsi_corrct,
		&ett_scsi_reassign_blocks,
		&ett_scsi_ssu_immed,
		&ett_scsi_ssu_pwr,
		&ett_scsi_synccache,
		&ett_scsi_verify,
		&ett_scsi_wrverify,
		&ett_scsi_writesame,
		&ett_scsi_unmap,
		&ett_scsi_unmap_block_descriptor,
		&ett_scsi_lba_status_descriptor
	};

	/* Register the protocol name and description */
	proto_scsi_sbc = proto_register_protocol("SCSI_SBC", "SCSI_SBC", "scsi_sbc");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_scsi_sbc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_scsi_sbc(void)
{
}

