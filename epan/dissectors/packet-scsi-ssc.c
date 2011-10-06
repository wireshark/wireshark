/* based on SSC3 spec */
/* TODO:
 * dissect READPOSITION data
 * dissect REPORTDENSITYSUPPORT data
 */
/* packet-scsi-ssc.c
 * Dissector for the SCSI SSC commandset
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
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-ssc.h"
#include "packet-scsi-smc.h"


static int proto_scsi_ssc		= -1;
int hf_scsi_ssc_opcode			= -1;
static int hf_scsi_ssc_rdwr6_xferlen	= -1;
static int hf_scsi_ssc_ver16_verlen	= -1;
static int hf_scsi_ssc_locate10_loid	= -1;
static int hf_scsi_ssc_locate16_loid	= -1;
static int hf_scsi_ssc_space6_code	= -1;
static int hf_scsi_ssc_space6_count	= -1;
static int hf_scsi_ssc_space16_count	= -1;
static int hf_scsi_ssc_erase_flags		= -1;
static int hf_scsi_ssc_fcs			= -1;
static int hf_scsi_ssc_lcs			= -1;
static int hf_scsi_ssc_erase_immed		= -1;
static int hf_scsi_ssc_long			= -1;
static int hf_scsi_ssc_partition		= -1;
static int hf_scsi_ssc_lbi			= -1;
static int hf_scsi_ssc_verify			= -1;
static int hf_scsi_ssc_immed			= -1;
static int hf_scsi_ssc_formatmedium_flags	= -1;
static int hf_scsi_ssc_format			= -1;
static int hf_scsi_ssc_rdwr10_xferlen		= -1;
static int hf_scsi_ssc_loadunload_immed_flags	= -1;
static int hf_scsi_ssc_loadunload_flags		= -1;
static int hf_scsi_ssc_hold			= -1;
static int hf_scsi_ssc_eot			= -1;
static int hf_scsi_ssc_reten			= -1;
static int hf_scsi_ssc_load			= -1;
static int hf_scsi_ssc_locate_flags		= -1;
static int hf_scsi_ssc_bt			= -1;
static int hf_scsi_ssc_cp			= -1;
static int hf_scsi_ssc_dest_type		= -1;
static int hf_scsi_ssc_bam_flags		= -1;
static int hf_scsi_ssc_bam			= -1;
static int hf_scsi_ssc_read6_flags		= -1;
static int hf_scsi_ssc_sili			= -1;
static int hf_scsi_ssc_fixed			= -1;
static int hf_scsi_ssc_bytord			= -1;
static int hf_scsi_ssc_bytcmp			= -1;
static int hf_scsi_ssc_verify16_immed		= -1;
static int hf_scsi_ssc_medium_type		= -1;
static int hf_scsi_ssc_media			= -1;
static int hf_scsi_ssc_capacity_prop_value	= -1;

static gint ett_scsi_erase			= -1;
static gint ett_scsi_formatmedium		= -1;
static gint ett_scsi_loadunload_immed		= -1;
static gint ett_scsi_loadunload			= -1;
static gint ett_scsi_locate			= -1;
static gint ett_scsi_bam			= -1;
static gint ett_scsi_read6			= -1;


static void
dissect_ssc_read6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *read6_fields[] = {
	&hf_scsi_ssc_sili,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, read6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_recoverbuffereddata (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *recover_fields[] = {
	&hf_scsi_ssc_sili,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, recover_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_reportdensitysupport (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rd_fields[] = {
	&hf_scsi_ssc_medium_type,
	&hf_scsi_ssc_media,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if(!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, rd_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    } else {
        /* XXX decode the data */
    }
}

static void
dissect_ssc_readreverse6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rr6_fields[] = {
	&hf_scsi_ssc_bytord,
	&hf_scsi_ssc_sili,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, rr6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_read16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *read6_fields[] = {
	&hf_scsi_ssc_sili,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, read6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_write16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *write16_fields[] = {
	&hf_scsi_ssc_fcs,
	&hf_scsi_ssc_lcs,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, write16_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_writefilemarks16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *wf16_fields[] = {
	&hf_scsi_ssc_fcs,
	&hf_scsi_ssc_lcs,
	&hf_scsi_ssc_immed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, wf16_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_verify16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *verify16_fields[] = {
	&hf_scsi_ssc_verify16_immed,
	&hf_scsi_ssc_bytcmp,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, verify16_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_ver16_verlen, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_verify6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *verify6_fields[] = {
	&hf_scsi_ssc_verify16_immed,
	&hf_scsi_ssc_bytcmp,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, verify6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_ver16_verlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_readreverse16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rr16_fields[] = {
	&hf_scsi_ssc_bytord,
	&hf_scsi_ssc_sili,
	&hf_scsi_ssc_fixed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, rr16_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+11, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_write6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *write6_fields[] = {
	&hf_scsi_ssc_immed,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, write6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_writefilemarks6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *wf6_fields[] = {
	&hf_scsi_ssc_immed,
	NULL
    };

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, wf6_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_loadunload (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *loadunload_immed_fields[] = {
	&hf_scsi_ssc_immed,
	NULL
    };
    static const int *loadunload_fields[] = {
	&hf_scsi_ssc_hold,
	&hf_scsi_ssc_eot,
	&hf_scsi_ssc_reten,
	&hf_scsi_ssc_load,
	NULL
    };

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);
    }

    if (!tree)
        return;


    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_loadunload_immed_flags,
            ett_scsi_loadunload_immed, loadunload_immed_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+3, hf_scsi_ssc_loadunload_flags,
            ett_scsi_loadunload, loadunload_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


static void
dissect_ssc_readblocklimits (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 granularity;

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
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

static void
dissect_ssc_rewind (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *rewind_fields[] = {
	&hf_scsi_ssc_immed,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);

        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags, ett_scsi_read6, rewind_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_setcapacity (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *sc_fields[] = {
	&hf_scsi_ssc_immed,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_read6_flags,
            ett_scsi_read6, sc_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_capacity_prop_value, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


static void
dissect_ssc_locate10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *locate_fields[] = {
	&hf_scsi_ssc_bt,
	&hf_scsi_ssc_cp,
	&hf_scsi_ssc_immed,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_locate_flags,
            ett_scsi_locate, locate_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_locate10_loid, tvb, offset+2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


static void
dissect_ssc_locate16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *locate_fields[] = {
	&hf_scsi_ssc_dest_type,
	&hf_scsi_ssc_cp,
	&hf_scsi_ssc_immed,
	NULL
    };
    static const int *bam_fields[] = {
	&hf_scsi_ssc_bam,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_locate_flags,
            ett_scsi_locate, locate_fields, FALSE);
        proto_tree_add_bitmask(tree, tvb, offset+1, hf_scsi_ssc_bam_flags,
            ett_scsi_bam, bam_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


static void
dissect_ssc_erase6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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

        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


static void
dissect_ssc_erase16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *erase16_fields[] = {
	&hf_scsi_ssc_fcs,
	&hf_scsi_ssc_lcs,
	&hf_scsi_ssc_erase_immed,
	&hf_scsi_ssc_long,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_erase_flags,
            ett_scsi_erase, erase16_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_lbi, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_space6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_ssc_space6_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_space6_count, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static void
dissect_ssc_space16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_ssc_space6_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_space16_count, tvb, offset+3, 8, ENC_BIG_ENDIAN);
        proto_tree_add_text (tree, tvb, offset+11, 2,
                             "Parameter Len: %u",
                             tvb_get_ntohs (tvb, offset+11));
        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}

static const value_string space6_code_vals[] = {
    {0,	"Logical Blocks"},
    {1,	"Filemarks"},
    {2,	"Sequential Filemarks"},
    {3,	"End-Of-Data"},
    {0, NULL}
};

static const value_string format_vals[] = {
    {0x0, "Use default format"},
    {0x1, "Partition medium"},
    {0x2, "Default format then partition"},
    {0, NULL}
};

static const value_string dest_type_vals[] = {
    {0, "Logical Object Identifier"},
    {1, "Logical File Identifier"},
    {0, NULL}
};

static void
dissect_ssc_formatmedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    static const int *formatmedium_fields[] = {
	&hf_scsi_ssc_verify,
	&hf_scsi_ssc_immed,
	NULL
    };

    if (!tree)
        return;

    if (isreq && iscdb) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_ssc_formatmedium_flags,
            ett_scsi_formatmedium, formatmedium_fields, FALSE);
        proto_tree_add_item (tree, hf_scsi_ssc_format, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr10_xferlen, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
}


#define BCU  0x20
#define BYCU 0x10
#define MPU  0x08
#define BPU  0x04

static void
dissect_ssc_readposition (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
            cdata->itlq->flags = service_action;
        }
        proto_tree_add_text (tree, tvb, offset+6, 2,
                             "Parameter Len: %u",
                             tvb_get_ntohs (tvb, offset+6));
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, FALSE);
    }
    else if (!isreq) {
        if (cdata)
            service_action = cdata->itlq->flags;
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

            proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset, 1, ENC_BIG_ENDIAN);
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
                                     "Block Number: %" G_GINT64_MODIFIER "u",
                                     tvb_get_ntoh64 (tvb, offset));
                 offset += 8;
            } else
                offset += 12;

            if (!(flags & MPU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "File Number: %" G_GINT64_MODIFIER "u",
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Set Number: %" G_GINT64_MODIFIER "u",
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

            proto_tree_add_item (tree, hf_scsi_ssc_partition, tvb, offset, 1, ENC_BIG_ENDIAN);
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
                                     "First Block Location: %" G_GINT64_MODIFIER "u",
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Last Block Location: %" G_GINT64_MODIFIER "u",
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;
            } else
                offset += 16;

            offset += 1; /* reserved */

            if (!(flags & BYCU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Number of Bytes in Buffer: %" G_GINT64_MODIFIER "u",
                                     tvb_get_ntoh64 (tvb, offset));
            }
            offset += 8;
            break;

        default:
            break;
        }
    }
}





/* SSC Commands */
const value_string scsi_ssc_vals[] = {
    {SCSI_SSC_ERASE_6                      , "Erase(6)"},
    {SCSI_SSC_ERASE_16                     , "Erase(16)"},
    {SCSI_SPC_EXTCOPY                      , "Extended Copy"},
    {SCSI_SSC_FORMAT_MEDIUM                , "Format Medium"},
    {SCSI_SPC_INQUIRY                      , "Inquiry"},
    {SCSI_SSC_LOAD_UNLOAD                  , "Load Unload"},
    {SCSI_SSC_LOCATE_10                    , "Locate(10)"},
    {SCSI_SSC_LOCATE_16                    , "Locate(16)"},
    {SCSI_SPC_LOGSELECT                    , "Log Select"},
    {SCSI_SPC_LOGSENSE                     , "Log Sense"},
    {SCSI_SPC_MODESELECT6                  , "Mode Select(6)"},
    {SCSI_SPC_RESERVE6                     , "Reserve(6)"},
    {SCSI_SPC_RELEASE6                     , "Release(6)"},
    {SCSI_SPC_MODESELECT10                 , "Mode Select(10)"},
    {SCSI_SPC_MODESENSE6                   , "Mode Sense(6)"},
    {SCSI_SPC_MODESENSE10                  , "Mode Sense(10)"},
    {SCSI_SMC_MOVE_MEDIUM                  , "Move Medium"},
    {SCSI_SMC_MOVE_MEDIUM_ATTACHED         , "Move Medium Attached"},
    {SCSI_SPC_PERSRESVIN                   , "Persistent Reserve In"},
    {SCSI_SPC_PERSRESVOUT                  , "Persistent Reserve Out"},
    {SCSI_SPC_PREVMEDREMOVAL               , "Prevent/Allow Medium Removal"},
    {SCSI_SSC_READ6                        , "Read(6)"},
    {SCSI_SSC_READ_16                      , "Read(16)"},
    {SCSI_SSC_READ_BLOCK_LIMITS            , "Read Block Limits"},
    {SCSI_SMC_READ_ELEMENT_STATUS          , "Read Element Status"},
    {SCSI_SMC_READ_ELEMENT_STATUS_ATTACHED , "Read Element Status Attached"},
    {SCSI_SSC_READ_POSITION                , "Read Position"},
    {SCSI_SSC_READ_REVERSE_6               , "Read Reverse(6)"},
    {SCSI_SSC_READ_REVERSE_16              , "Read Reverse(16)"},
    {SCSI_SSC_RECOVER_BUFFERED_DATA        , "Recover Buffered Data"},
    {SCSI_SSC_REPORT_DENSITY_SUPPORT       , "Report Density Support"},
    {SCSI_SPC_REPORTLUNS                   , "Report LUNs"},
    {SCSI_SPC_REQSENSE                     , "Request Sense"},
    {SCSI_SSC_REWIND                       , "Rewind"},
    {SCSI_SPC_SENDDIAG                     , "Send Diagnostic"},
    {SCSI_SSC_SET_CAPACITY                 , "Set Capacity"},
    {SCSI_SSC_SPACE_6                      , "Space(6)"},
    {SCSI_SSC_SPACE_16                     , "Space(16)"},
    {SCSI_SPC_TESTUNITRDY                  , "Test Unit Ready"},
    {SCSI_SSC_VERIFY_6                     , "Verify(6)"},
    {SCSI_SSC_VERIFY_16                    , "Verify(16)"},
    {SCSI_SSC_WRITE6                       , "Write(6)"},
    {SCSI_SSC_WRITE_16                     , "Write(16)"},
    {SCSI_SPC_WRITEBUFFER                  , "Write Buffer"},
    {SCSI_SSC_WRITE_FILEMARKS_16           , "Write Filemarks(16)"},
    {SCSI_SSC_WRITE_FILEMARKS_6            , "Write Filemarks(6)"},
    {0, NULL}
};


scsi_cdb_table_t scsi_ssc_table[256] = {
/*SPC 0x00*/{dissect_spc_testunitready},
/*SSC 0x01*/{dissect_ssc_rewind},
/*SSC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc_requestsense},
/*SSC 0x04*/{dissect_ssc_formatmedium},
/*SSC 0x05*/{dissect_ssc_readblocklimits},
/*SSC 0x06*/{NULL},
/*SSC 0x07*/{NULL},
/*SSC 0x08*/{dissect_ssc_read6},
/*SSC 0x09*/{NULL},
/*SSC 0x0a*/{dissect_ssc_write6},
/*SSC 0x0b*/{dissect_ssc_setcapacity},
/*SSC 0x0c*/{NULL},
/*SSC 0x0d*/{NULL},
/*SSC 0x0e*/{NULL},
/*SSC 0x0f*/{dissect_ssc_readreverse6},
/*SSC 0x10*/{dissect_ssc_writefilemarks6},
/*SSC 0x11*/{dissect_ssc_space6},
/*SPC 0x12*/{dissect_spc_inquiry},
/*SSC 0x13*/{dissect_ssc_verify6},
/*SSC 0x14*/{dissect_ssc_recoverbuffereddata},
/*SPC 0x15*/{dissect_spc_modeselect6},
/*SSC 0x16*/{dissect_spc_reserve6},
/*SSC 0x17*/{dissect_spc_release6},
/*SSC 0x18*/{NULL},
/*SSC 0x19*/{dissect_ssc_erase6},
/*SPC 0x1a*/{dissect_spc_modesense6},
/*SSC 0x1b*/{dissect_ssc_loadunload},
/*SSC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc_senddiagnostic},
/*SSC 0x1e*/{dissect_spc_preventallowmediaremoval},
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
/*SSC 0x2b*/{dissect_ssc_locate10},
/*SSC 0x2c*/{NULL},
/*SSC 0x2d*/{NULL},
/*SSC 0x2e*/{NULL},
/*SSC 0x2f*/{NULL},
/*SSC 0x30*/{NULL},
/*SSC 0x31*/{NULL},
/*SSC 0x32*/{NULL},
/*SSC 0x33*/{NULL},
/*SSC 0x34*/{dissect_ssc_readposition},
/*SSC 0x35*/{NULL},
/*SSC 0x36*/{NULL},
/*SSC 0x37*/{NULL},
/*SSC 0x38*/{NULL},
/*SSC 0x39*/{NULL},
/*SSC 0x3a*/{NULL},
/*SPC 0x3b*/{dissect_spc_writebuffer},
/*SSC 0x3c*/{NULL},
/*SSC 0x3d*/{NULL},
/*SSC 0x3e*/{NULL},
/*SSC 0x3f*/{NULL},
/*SSC 0x40*/{NULL},
/*SSC 0x41*/{NULL},
/*SSC 0x42*/{NULL},
/*SSC 0x43*/{NULL},
/*SSC 0x44*/{dissect_ssc_reportdensitysupport},
/*SSC 0x45*/{NULL},
/*SSC 0x46*/{NULL},
/*SSC 0x47*/{NULL},
/*SSC 0x48*/{NULL},
/*SSC 0x49*/{NULL},
/*SSC 0x4a*/{NULL},
/*SSC 0x4b*/{NULL},
/*SPC 0x4c*/{dissect_spc_logselect},
/*SPC 0x4d*/{dissect_spc_logsense},
/*SSC 0x4e*/{NULL},
/*SSC 0x4f*/{NULL},
/*SSC 0x50*/{NULL},
/*SSC 0x51*/{NULL},
/*SSC 0x52*/{NULL},
/*SSC 0x53*/{NULL},
/*SSC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc_modeselect10},
/*SSC 0x56*/{NULL},
/*SSC 0x57*/{NULL},
/*SSC 0x58*/{NULL},
/*SSC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc_modesense10},
/*SSC 0x5b*/{NULL},
/*SSC 0x5c*/{NULL},
/*SSC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc_persistentreservein},
/*SPC 0x5f*/{dissect_spc_persistentreserveout},
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
/*SSC 0x80*/{dissect_ssc_writefilemarks16},
/*SSC 0x81*/{dissect_ssc_readreverse16},
/*SSC 0x82*/{NULL},
/*SPC 0x83*/{dissect_spc_extcopy},
/*SSC 0x84*/{NULL},
/*SSC 0x85*/{NULL},
/*SSC 0x86*/{NULL},
/*SSC 0x87*/{NULL},
/*SSC 0x88*/{dissect_ssc_read16},
/*SSC 0x89*/{NULL},
/*SSC 0x8a*/{dissect_ssc_write16},
/*SSC 0x8b*/{NULL},
/*SSC 0x8c*/{NULL},
/*SSC 0x8d*/{NULL},
/*SSC 0x8e*/{NULL},
/*SSC 0x8f*/{dissect_ssc_verify16},
/*SSC 0x90*/{NULL},
/*SSC 0x91*/{dissect_ssc_space16},
/*SSC 0x92*/{dissect_ssc_locate16},
/*SSC 0x93*/{dissect_ssc_erase16},
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
/*SPC 0xa0*/{dissect_spc_reportluns},
/*SSC 0xa1*/{NULL},
/*SSC 0xa2*/{NULL},
/*SSC 0xa3*/{NULL},
/*SSC 0xa4*/{NULL},
/*SSC 0xa5*/{dissect_smc_movemedium},
/*SSC 0xa6*/{NULL},
/*SSC 0xa7*/{dissect_smc_movemedium},
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
/*SSC 0xb4*/{dissect_smc_readelementstatus},
/*SSC 0xb5*/{NULL},
/*SSC 0xb6*/{NULL},
/*SSC 0xb7*/{NULL},
/*SSC 0xb8*/{dissect_smc_readelementstatus},
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



void
proto_register_scsi_ssc(void)
{
	static hf_register_info hf[] = {
        { &hf_scsi_ssc_opcode,
          {"SSC Opcode", "scsi.ssc.opcode", FT_UINT8, BASE_HEX,
           VALS (scsi_ssc_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_rdwr6_xferlen,
          {"Transfer Length", "scsi.ssc.rdwr6.xferlen", FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_ver16_verlen,
          {"Verification Length", "scsi.ssc.verify16.verify_len", FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_locate10_loid,
          {"Logical Object Identifier", "scsi.ssc.locate10.loid", FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_locate16_loid,
          {"Logical Identifier", "scsi.ssc.locate16.loid", FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_space6_count,
          {"Count", "scsi.ssc.space6.count", FT_INT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_space6_code,
          {"Code", "scsi.ssc.space6.code", FT_UINT8, BASE_HEX,
          VALS(space6_code_vals), 0x0f,
           NULL, HFILL}},
        { &hf_scsi_ssc_space16_count,
          {"Count", "scsi.ssc.space16.count", FT_UINT64, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_scsi_ssc_rdwr10_xferlen,
          {"Transfer Length", "scsi.ssc.rdwr10.xferlen", FT_UINT16, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_scsi_ssc_erase_flags,
          {"Flags", "scsi.ssc.erase_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_fcs,
          {"FCS", "scsi.ssc.fcs", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_ssc_lcs,
          {"LCS", "scsi.ssc.lcs", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_ssc_erase_immed,
          {"IMMED", "scsi.ssc.erase_immed", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_long,
          {"LONG", "scsi.ssc.long", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_partition,
          {"Partition", "scsi.ssc.partition", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_lbi,
          {"Logical Block Identifier", "scsi.ssc.lbi", FT_UINT64, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_verify,
          {"VERIFY", "scsi.ssc.verify", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_immed,
          {"IMMED", "scsi.ssc.immed", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_formatmedium_flags,
          {"Flags", "scsi.ssc.formatmedium_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_format,
          {"Format", "scsi.ssc.format", FT_UINT8, BASE_HEX,
           VALS(format_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_ssc_loadunload_immed_flags,
          {"Immed", "scsi.ssc.loadunload_immed_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_loadunload_flags,
          {"Flags", "scsi.ssc.loadunload_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_hold,
          {"HOLD", "scsi.ssc.hold", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_ssc_eot,
          {"EOT", "scsi.ssc.eot", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_ssc_reten,
          {"RETEN", "scsi.ssc.reten", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_load,
          {"LOAD", "scsi.ssc.load", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_locate_flags,
          {"Flags", "scsi.ssc.locate_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_bt,
          {"BT", "scsi.ssc.bt", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_ssc_cp,
          {"CP", "scsi.ssc.cp", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_dest_type,
          {"Dest Type", "scsi.ssc.dest_type", FT_UINT8, BASE_HEX,
           VALS(dest_type_vals), 0x18, NULL, HFILL}},
        { &hf_scsi_ssc_bam_flags,
          {"Flags", "scsi.ssc.bam_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_bam,
          {"BAM", "scsi.ssc.bam", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_read6_flags,
          {"Flags", "scsi.ssc.read6_flags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_ssc_sili,
          {"SILI", "scsi.ssc.sili", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_fixed,
          {"FIXED", "scsi.ssc.fixed", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_bytord,
          {"BYTORD", "scsi.ssc.bytord", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_ssc_bytcmp,
          {"BYTCMP", "scsi.ssc.bytcmp", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_verify16_immed,
          {"IMMED", "scsi.ssc.verify16_immed", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_ssc_medium_type,
          {"Medium Type", "scsi.ssc.medium_type", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_ssc_media,
          {"Media", "scsi.ssc.media", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_ssc_capacity_prop_value,
          {"Capacity Proportion Value", "scsi.ssc.cpv", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
	};


	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_scsi_erase,
		&ett_scsi_formatmedium,
		&ett_scsi_loadunload_immed,
		&ett_scsi_loadunload,
		&ett_scsi_locate,
		&ett_scsi_bam,
		&ett_scsi_read6
	};


	/* Register the protocol name and description */
	proto_scsi_ssc = proto_register_protocol("SCSI_SSC", "SCSI_SSC", "scsi_ssc");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_scsi_ssc, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_scsi_ssc(void)
{
}

