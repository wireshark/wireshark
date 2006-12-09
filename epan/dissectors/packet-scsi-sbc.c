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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
static int hf_scsi_sbc_ssu_immed		= -1;
static int hf_scsi_sbc_ssu_pwr_cond		= -1;
static int hf_scsi_sbc_ssu_loej			= -1;
static int hf_scsi_sbc_ssu_start		= -1;
static int hf_scsi_sbc_verify_dpo		= -1;
static int hf_scsi_sbc_verify_blkvfy		= -1;
static int hf_scsi_sbc_verify_bytchk		= -1;
static int hf_scsi_sbc_verify_reladdr		= -1;
static int hf_scsi_sbc_verify_lba		= -1;
static int hf_scsi_sbc_verify_vlen		= -1;
static int hf_scsi_sbc_verify_vlen32		= -1;
static int hf_scsi_sbc_wrverify_ebp		= -1;
static int hf_scsi_sbc_wrverify_lba		= -1;
static int hf_scsi_sbc_wrverify_xferlen		= -1;
static int hf_scsi_sbc_wrverify_lba64		= -1;
static int hf_scsi_sbc_wrverify_xferlen32	= -1;
static int hf_scsi_sbc_readcapacity_flags	= -1;
static int hf_scsi_sbc_readcapacity_lba		= -1;
static int hf_scsi_sbc_readcapacity_pmi		= -1;
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
static int hf_scsi_sbc_prefetch_group		= -1;

static gint ett_scsi_format_unit		= -1;
static gint ett_scsi_prefetch			= -1;




static void
dissect_sbc_formatunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                         guint offset, gboolean isreq, gboolean iscdb,
                         guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;
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
	proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_formatunit_flags, ett_scsi_format_unit, fuflags_fields, FALSE);

        proto_tree_add_item (tree, hf_scsi_sbc_formatunit_vendor, tvb, offset+1,
                             1, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_formatunit_interleave, tvb, offset+2,
                             2, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
    /* TODO : add dissection of DATA */
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
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_lba, tvb, offset, 3, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr6_xferlen, tvb, offset+3, 1, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_sbc_prefetch10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;
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
	proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_prefetch_flags, ett_scsi_prefetch, prefetch_fields, FALSE);

        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, 0);

        proto_tree_add_item (tree, hf_scsi_sbc_prefetch_group, tvb, offset+5, 1, 0);

        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, 0);
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}
static void
dissect_sbc_prefetch16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;
    static const int *prefetch_fields[] = {
	&hf_scsi_sbc_prefetch_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(LBA: %" PRIu64 ", Len: %u)",
                             tvb_get_ntoh64 (tvb, offset+1),
                             tvb_get_ntohl (tvb, offset+9));
    }

    if (tree && isreq && iscdb) {
	proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_sbc_prefetch_flags, ett_scsi_prefetch, prefetch_fields, FALSE);

        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_prefetch_group, tvb, offset+13, 1, 0);

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_xferlen, tvb, offset+6, 2, 0);
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr10_lba, tvb, offset+1, 4, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+5, 4, 0);
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_read_flags, tvb, offset, 1,
                                    flags,
                                    "DPO = %u, FUA = %u, RelAddr = %u",
                                    flags & 0x10, flags & 0x8, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr16_lba, tvb, offset+1, 8, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_rdwr12_xferlen, tvb, offset+9, 4, 0);
        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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

void
dissect_sbc2_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                            guint offset, gboolean isreq _U_, gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (!tree || !iscdb)
        return;

    proto_tree_add_boolean (tree, hf_scsi_sbc_ssu_immed, tvb, offset, 1, 0);
    proto_tree_add_uint (tree, hf_scsi_sbc_ssu_pwr_cond, tvb, offset+3, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_sbc_ssu_loej, tvb, offset+3, 1, 0);
    proto_tree_add_boolean (tree, hf_scsi_sbc_ssu_start, tvb, offset+3, 1, 0);

    flags = tvb_get_guint8 (tvb, offset+4);
    proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                flags,
                                "Vendor Unique = %u, NACA = %u, Link = %u",
                                flags & 0xC0, flags & 0x4, flags & 0x1);
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen, tvb, offset+7, 2, 0);
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen32, tvb, offset+6, 4, 0);
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_blkvfy, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_lba, tvb, offset+2, 8, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_vlen, tvb, offset+10, 4, 0);
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen, tvb, offset+7,
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba, tvb, offset+2, 4, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen32, tvb, offset+6,
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
         proto_tree_add_item (tree, hf_scsi_sbc_verify_dpo, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_ebp, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_bytchk, tvb, offset+1, 1, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_verify_reladdr, tvb, offset+1, 1,
                              0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_lba64, tvb, offset+2, 8, 0);
         proto_tree_add_item (tree, hf_scsi_sbc_wrverify_xferlen32, tvb, offset+10,
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_readcapacity_flags, tvb,
                                    offset, 1, flags,
                                    "LongLBA = %u, RelAddr = %u",
                                    flags & 0x2, flags & 0x1);
        proto_tree_add_item (tree, hf_scsi_sbc_readcapacity_lba, tvb, offset+1,
                             4, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_readcapacity_pmi, tvb, offset+7,
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_readdefdata_flags, tvb,
                                    offset, 1, flags, "PLIST = %u, GLIST = %u",
                                    flags & 0x10, flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_sbc_defect_list_format, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen16, tvb, offset+6, 2, 0);
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_readdefdata_flags, tvb,
                                    offset, 1, flags, "PLIST = %u, GLIST = %u",
                                    flags & 0x10, flags & 0x8);
        proto_tree_add_item (tree, hf_scsi_sbc_defect_list_format, tvb, offset, 1, 0);
        proto_tree_add_item (tree, hf_scsi_sbc_alloclen32, tvb, offset+5, 4, 0);
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

        proto_tree_add_uint_format (tree, hf_scsi_sbc_reassignblks_flags, tvb,
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

	        proto_tree_add_item (tree, hf_scsi_sbc_alloclen32, tvb, offset, 4, 0);
		offset += 4;

	        proto_tree_add_item (tree, hf_scsi_sbc_readcapacity_pmi, tvb, offset, 1, 0);
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


/* SBC Commands */
const value_string scsi_sbc_vals[] = {
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

scsi_cdb_table_t scsi_sbc_table[256] = {
/*SPC 0x00*/{dissect_spc3_testunitready},
/*SBC 0x01*/{NULL},
/*SBC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc3_requestsense},
/*SBC 0x04*/{dissect_sbc_formatunit},
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
/*SBC 0x34*/{dissect_sbc_prefetch10},
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
/*SBC 0x90*/{dissect_sbc_prefetch16},
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


void
proto_register_scsi_sbc(void)
{
	static hf_register_info hf[] = {
        { &hf_scsi_sbc_opcode,
          {"SBC Opcode", "scsi.sbc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_sbc_vals), 0x0, "", HFILL}},
        { &hf_scsi_sbc_formatunit_flags,
          {"Flags", "scsi.sbc.formatunit.flags", FT_UINT8, BASE_HEX, NULL, 0xF8,
           "", HFILL}},
        { &hf_scsi_sbc_defect_list_format,
          {"Defect List Format", "scsi.sbc.defect_list_format", FT_UINT8, BASE_DEC,
           NULL, 0x7, "", HFILL}},
        { &hf_scsi_sbc_formatunit_vendor,
          {"Vendor Unique", "scsi.sbc.formatunit.vendor", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_sbc_formatunit_interleave,
          {"Interleave", "scsi.sbc.formatunit.interleave", FT_UINT16, BASE_HEX,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_rdwr6_lba,
          {"Logical Block Address (LBA)", "scsi.sbc.rdwr6.lba", FT_UINT24, BASE_DEC,
           NULL, 0x0FFFFF, "", HFILL}},
        { &hf_scsi_sbc_rdwr6_xferlen,
          {"Transfer Length", "scsi.sbc.rdwr6.xferlen", FT_UINT24, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_sbc_rdwr10_lba,
          {"Logical Block Address (LBA)", "scsi.sbc.rdwr10.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_rdwr10_xferlen,
          {"Transfer Length", "scsi.sbc.rdwr10.xferlen", FT_UINT16, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_sbc_rdwr12_xferlen,
          {"Transfer Length", "scsi.sbc.rdwr12.xferlen", FT_UINT32, BASE_DEC, NULL,
           0x0, "", HFILL}},
        { &hf_scsi_sbc_rdwr16_lba,
          {"Logical Block Address (LBA)", "scsi.sbc.rdwr16.lba", FT_BYTES, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_ssu_immed,
          {"Immediate", "scsi.sbc.ssu.immediate", FT_BOOLEAN, 8, NULL,
           0x1, "", HFILL}},
        { &hf_scsi_sbc_ssu_pwr_cond,
          {"Power Conditions", "scsi.sbc.ssu.pwr", FT_UINT8, BASE_HEX,
           VALS (scsi_ssu_pwrcnd_val), 0xF0, "", HFILL}},
        { &hf_scsi_sbc_ssu_loej,
          {"LOEJ", "scsi.sbc.ssu.loej", FT_BOOLEAN, 8, NULL, 0x2, "",
           HFILL}},
        { &hf_scsi_sbc_ssu_start,
          {"Start", "scsi.sbc.ssu.start", FT_BOOLEAN, 8, NULL, 0x1,
           "", HFILL}},
        { &hf_scsi_sbc_verify_dpo,
          {"DPO", "scsi.sbc.verify.dpo", FT_BOOLEAN, 8, NULL, 0x10, "",
           HFILL}},
        { &hf_scsi_sbc_verify_blkvfy,
          {"BLKVFY", "scsi.sbc.verify.blkvfy", FT_BOOLEAN, 8, NULL, 0x4,
           "", HFILL}},
        { &hf_scsi_sbc_verify_bytchk,
          {"BYTCHK", "scsi.sbc.verify.bytchk", FT_BOOLEAN, 8, NULL, 0x2,
           "", HFILL}},
        { &hf_scsi_sbc_verify_reladdr,
          {"RELADDR", "scsi.sbc.verify.reladdr", FT_BOOLEAN, 8, NULL,
           0x1, "", HFILL}},
        { &hf_scsi_sbc_verify_lba,
          {"LBA", "scsi.sbc.verify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_verify_vlen,
          {"Verification Length", "scsi.sbc.verify.vlen", FT_UINT16,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_verify_vlen32,
          {"Verification Length", "scsi.sbc.verify.vlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_wrverify_ebp,
          {"EBP", "scsi.sbc.wrverify.ebp", FT_BOOLEAN, 8, NULL, 0x4, "",
           HFILL}},
        { &hf_scsi_sbc_wrverify_lba,
          {"LBA", "scsi.sbc.wrverify.lba", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_wrverify_xferlen,
          {"Transfer Length", "scsi.sbc.wrverify.xferlen", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_wrverify_lba64,
          {"LBA", "scsi.sbc.wrverify.lba64", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_sbc_wrverify_xferlen32,
          {"Transfer Length", "scsi.sbc.wrverify.xferlen32", FT_UINT32,
           BASE_DEC, NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_readcapacity_flags,
          {"Flags", "scsi.sbc.readcapacity.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_sbc_readcapacity_lba,
          {"Logical Block Address", "scsi.sbc.readcapacity.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_readcapacity_pmi,
          {"PMI", "scsi.sbc.readcapacity.pmi", FT_UINT8, BASE_DEC, NULL, 0x1, "",
           HFILL}},
        { &hf_scsi_sbc_readdefdata_flags,
          {"Flags", "scsi.sbc.readdefdata.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_reassignblks_flags,
          {"Flags", "scsi.sbc.reassignblks.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_read_flags,
          {"Flags", "scsi.sbc.read.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_alloclen32,
          {"Allocation Length", "scsi.sbc.alloclen32", FT_UINT32, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_alloclen16,
          {"Allocation Length", "scsi.sbc.alloclen16", FT_UINT16, BASE_DEC,
           NULL, 0x0, "", HFILL}},
        { &hf_scsi_sbc_fuflags_fmtpinfo,
          {"FMTPINFO", "scsi.sbc.format_unit.fmtpinfo", FT_BOOLEAN, 8,
           NULL, 0x80, "", HFILL}},
        { &hf_scsi_sbc_fuflags_rto_req,
          {"RTO_REQ", "scsi.sbc.format_unit.rto_req", FT_BOOLEAN, 8,
           NULL, 0x40, "", HFILL}},
        { &hf_scsi_sbc_fuflags_longlist,
          {"LONGLIST", "scsi.sbc.format_unit.longlist", FT_BOOLEAN, 8,
           NULL, 0x20, "", HFILL}},
        { &hf_scsi_sbc_fuflags_fmtdata,
          {"FMTDATA", "scsi.sbc.format_unit.fmtdata", FT_BOOLEAN, 8,
           NULL, 0x10, "", HFILL}},
        { &hf_scsi_sbc_fuflags_cmplist,
          {"CMPLIST", "scsi.sbc.format_unit.cmplist", FT_BOOLEAN, 8,
           NULL, 0x08, "", HFILL}},
        { &hf_scsi_sbc_prefetch_flags,
          {"Flags", "scsi.sbc.prefetch.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_scsi_sbc_prefetch_immed,
          {"Immediate", "scsi.sbc.prefetch.immediate", FT_BOOLEAN, 8, NULL,
           0x2, "", HFILL}},
        { &hf_scsi_sbc_prefetch_group,
          {"Group", "scsi.sbc.prefetch.group", FT_UINT8, BASE_HEX, NULL,
           0x1f, "", HFILL}},
	};


	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_scsi_format_unit,
		&ett_scsi_prefetch
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

