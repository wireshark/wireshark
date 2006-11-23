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
#include <string.h>
#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-ssc.h"
#include "packet-scsi-smc.h"


static int proto_scsi_ssc		= -1;
int hf_scsi_ssc_opcode			= -1;
static int hf_scsi_ssc_rdwr6_xferlen	= -1;
static int hf_scsi_ssc_locate10_loid	= -1;
static int hf_scsi_ssc_locate16_loid	= -1;
static int hf_scsi_ssc_space6_count	= -1;
static int hf_scsi_ssc_space16_count	= -1;
static int hf_scsi_ssc_rdwr10_xferlen	= -1;


static void
dissect_ssc2_read6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "SILI: %u, FIXED: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3, 0);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_write6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "FIXED: %u", flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3,
                             FALSE);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_writefilemarks6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Len: %u)",
                             tvb_get_ntoh24 (tvb, offset+1));
    }

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "WSMK: %u, IMMED: %u",
                             (flags & 0x02) >> 1, flags & 0x01);
        proto_tree_add_item (tree, hf_scsi_ssc_rdwr6_xferlen, tvb, offset+1, 3,
                             FALSE);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_loadunload (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);

        if (!tree)
            return;

        proto_tree_add_text (tree, tvb, offset, 1,
                             "Immed: %u", tvb_get_guint8 (tvb, offset) & 0x01);
        flags = tvb_get_guint8 (tvb, offset+3);
        proto_tree_add_text (tree, tvb, offset+3, 1,
                             "Hold: %u, EOT: %u, Reten: %u, Load: %u",
                             (flags & 0x08) >> 3, (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1, (flags & 0x01));
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_readblocklimits (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags, granularity;

    if (!tree)
        return;

    if (isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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
dissect_ssc2_rewind (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (check_col (pinfo->cinfo, COL_INFO))
            col_append_fstr (pinfo->cinfo, COL_INFO, "(Immed: %u)",
                             tvb_get_guint8 (tvb, offset) & 0x01);

        if (!tree)
            return;

        proto_tree_add_text (tree, tvb, offset, 1,
                             "Immed: %u", tvb_get_guint8 (tvb, offset) & 0x01);
        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_locate10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "BT: %u, CP: %u, IMMED: %u",
                             (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_item (tree, hf_scsi_ssc_locate10_loid, tvb, offset+2, 4, 0);

        flags = tvb_get_guint8 (tvb, offset+7);
        proto_tree_add_text (tree, tvb, offset+7, 1,
                             "Partition: %u",
                            flags);

        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_locate16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "DEST_TYPE: %u, CP: %u, IMMED: %u",
                             (flags & 0x18) >> 3,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        flags = tvb_get_guint8 (tvb, offset+2);
        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Partition: %u",
                            flags);

        proto_tree_add_item (tree, hf_scsi_ssc_locate16_loid, tvb, offset+3, 8, 0);

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_erase6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_erase16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "FCS: %u, LCS: %u, IMMED: %u, LONG: %u",
                             (flags & 0x08) >> 3,
                             (flags & 0x04) >> 2,
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_text (tree, tvb, offset+2, 1,
                             "Partition: %u", tvb_get_guint8(tvb,offset+2));

        proto_tree_add_text (tree, tvb, offset+3, 8,
                             "Logical Object Identifier: 0x%02x%02x%02x%02x%02x%02x%02x%02x",
                             tvb_get_guint8(tvb,offset+3),
                             tvb_get_guint8(tvb,offset+4),
                             tvb_get_guint8(tvb,offset+5),
                             tvb_get_guint8(tvb,offset+6),
                             tvb_get_guint8(tvb,offset+7),
                             tvb_get_guint8(tvb,offset+8),
                             tvb_get_guint8(tvb,offset+9),
                             tvb_get_guint8(tvb,offset+10));

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


static void
dissect_ssc2_space6 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "CODE: %u",
                             flags & 0x0f);

        proto_tree_add_item (tree, hf_scsi_ssc_space6_count, tvb, offset+1, 3, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_space16 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "CODE: %u",
                             flags & 0x0f);

        proto_tree_add_item (tree, hf_scsi_ssc_space16_count, tvb, offset+3, 8, 0);

        proto_tree_add_text (tree, tvb, offset+11, 2,
                             "Parameter Len: %u",
                             tvb_get_ntohs (tvb, offset+11));

        flags = tvb_get_guint8 (tvb, offset+14);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+14, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}

static void
dissect_ssc2_formatmedium (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    guint8 flags;

    if (isreq && iscdb) {
        if (!tree)
            return;

        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "VERIFY: %u, IMMED: %u",
                             (flags & 0x02) >> 1,
                             flags & 0x01);

        proto_tree_add_text (tree, tvb, offset+1, 1,
                             "Format: 0x%02x", tvb_get_guint8(tvb,offset+1)&0x0f);

        proto_tree_add_item (tree, hf_scsi_ssc_rdwr10_xferlen, tvb, offset+2, 2, 0);

        flags = tvb_get_guint8 (tvb, offset+4);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+4, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
    }
}


#define BCU  0x20
#define BYCU 0x10
#define MPU  0x08
#define BPU  0x04

static void
dissect_ssc2_readposition (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
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
        flags = tvb_get_guint8 (tvb, offset+8);
        proto_tree_add_uint_format (tree, hf_scsi_control, tvb, offset+8, 1,
                                    flags,
                                    "Vendor Unique = %u, NACA = %u, Link = %u",
                                    flags & 0xC0, flags & 0x4, flags & 0x1);
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

            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Partition Number: %u",
                                 tvb_get_guint8 (tvb, offset));
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
                                     "Block Number: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                 offset += 8;
            } else
                offset += 12;

            if (!(flags & MPU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "File Number: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Set Number: %" PRIu64,
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

            proto_tree_add_text (tree, tvb, offset, 1,
                                 "Partition Number: %u",
                                 tvb_get_guint8 (tvb, offset));
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
                                     "First Block Location: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;

                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Last Block Location: %" PRIu64,
                                     tvb_get_ntoh64 (tvb, offset));
                offset += 8;
            } else
                offset += 16;

            offset += 1; /* reserved */

            if (!(flags & BYCU)) {
                proto_tree_add_text (tree, tvb, offset, 8,
                                     "Number of Bytes in Buffer: %" PRIu64,
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
    {SCSI_SSC2_ERASE_6                     , "Erase(6)"},
    {SCSI_SSC2_ERASE_16                    , "Erase(16)"},
    {SCSI_SPC2_EXTCOPY                     , "Extended Copy"},
    {SCSI_SSC2_FORMAT_MEDIUM               , "Format Medium"},
    {SCSI_SPC2_INQUIRY                     , "Inquiry"},
    {SCSI_SSC2_LOAD_UNLOAD                 , "Load Unload"},
    {SCSI_SSC2_LOCATE_10                   , "Locate(10)"},
    {SCSI_SSC2_LOCATE_16                   , "Locate(16)"},
    {SCSI_SPC2_LOGSELECT                   , "Log Select"},
    {SCSI_SPC2_LOGSENSE                    , "Log Sense"},
    {SCSI_SPC2_MODESELECT6                 , "Mode Select(6)"},
    {SCSI_SPC2_RESERVE6                    , "Reserve(6)"},
    {SCSI_SPC2_RELEASE6                    , "Release(6)"},
    {SCSI_SPC2_MODESELECT10                , "Mode Select(10)"},
    {SCSI_SPC2_MODESENSE6                  , "Mode Sense(6)"},
    {SCSI_SPC2_MODESENSE10                 , "Mode Sense(10)"},
    {SCSI_SMC2_MOVE_MEDIUM                 , "Move Medium"},
    {SCSI_SMC2_MOVE_MEDIUM_ATTACHED        , "Move Medium Attached"},
    {SCSI_SPC2_PERSRESVIN                  , "Persistent Reserve In"},
    {SCSI_SPC2_PERSRESVOUT                 , "Persistent Reserve Out"},
    {SCSI_SPC2_PREVMEDREMOVAL              , "Prevent/Allow Medium Removal"},
    {SCSI_SSC2_READ6                       , "Read(6)"},
    {SCSI_SSC2_READ_16                     , "Read(16)"},
    {SCSI_SSC2_READ_BLOCK_LIMITS           , "Read Block Limits"},
    {SCSI_SMC2_READ_ELEMENT_STATUS         , "Read Element Status"},
    {SCSI_SMC2_READ_ELEMENT_STATUS_ATTACHED, "Read Element Status Attached"},
    {SCSI_SSC2_READ_POSITION               , "Read Position"},
    {SCSI_SSC2_READ_REVERSE_6              , "Read Reverse(6)"},
    {SCSI_SSC2_READ_REVERSE_16             , "Read Reverse(16)"},
    {SCSI_SSC2_RECOVER_BUFFERED_DATA       , "Recover Buffered Data"},
    {SCSI_SSC2_REPORT_DENSITY_SUPPORT      , "Report Density Support"},
    {SCSI_SPC2_REPORTLUNS                  , "Report LUNs"},
    {SCSI_SPC2_REQSENSE                    , "Request Sense"},
    {SCSI_SSC2_REWIND                      , "Rewind"},
    {SCSI_SPC2_SENDDIAG                    , "Send Diagnostic"},
    {SCSI_SSC2_SET_CAPACITY                , "Set Capacity"},
    {SCSI_SSC2_SPACE_6                     , "Space(6)"},
    {SCSI_SSC2_SPACE_16                    , "Space(16)"},
    {SCSI_SPC2_TESTUNITRDY                 , "Test Unit Ready"},
    {SCSI_SSC2_VERIFY_6                    , "Verify(6)"},
    {SCSI_SSC2_VERIFY_16                   , "Verify(16)"},
    {SCSI_SSC2_WRITE6                      , "Write(6)"},
    {SCSI_SSC2_WRITE_16                    , "Write(16)"},
    {SCSI_SPC2_WRITEBUFFER                 , "Write Buffer"},
    {SCSI_SSC2_WRITE_FILEMARKS_16          , "Write Filemarks(16)"},
    {SCSI_SSC2_WRITE_FILEMARKS_6           , "Write Filemarks(6)"},
    {0, NULL},
};


scsi_cdb_table_t scsi_ssc_table[256] = {
/*SPC 0x00*/{dissect_spc3_testunitready},
/*SSC 0x01*/{dissect_ssc2_rewind},
/*SSC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc3_requestsense},
/*SSC 0x04*/{dissect_ssc2_formatmedium},
/*SSC 0x05*/{dissect_ssc2_readblocklimits},
/*SSC 0x06*/{NULL},
/*SSC 0x07*/{NULL},
/*SSC 0x08*/{dissect_ssc2_read6},
/*SSC 0x09*/{NULL},
/*SSC 0x0a*/{dissect_ssc2_write6},
/*SSC 0x0b*/{NULL},
/*SSC 0x0c*/{NULL},
/*SSC 0x0d*/{NULL},
/*SSC 0x0e*/{NULL},
/*SSC 0x0f*/{NULL},
/*SSC 0x10*/{dissect_ssc2_writefilemarks6},
/*SSC 0x11*/{dissect_ssc2_space6},
/*SPC 0x12*/{dissect_spc3_inquiry},
/*SSC 0x13*/{NULL},
/*SSC 0x14*/{NULL},
/*SPC 0x15*/{dissect_spc3_modeselect6},
/*SSC 0x16*/{dissect_spc2_reserve6},
/*SSC 0x17*/{dissect_spc2_release6},
/*SSC 0x18*/{NULL},
/*SSC 0x19*/{dissect_ssc2_erase6},
/*SPC 0x1a*/{dissect_spc3_modesense6},
/*SSC 0x1b*/{dissect_ssc2_loadunload},
/*SSC 0x1c*/{NULL},
/*SPC 0x1d*/{dissect_spc3_senddiagnostic},
/*SSC 0x1e*/{dissect_spc3_preventallowmediaremoval},
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
/*SSC 0x2b*/{dissect_ssc2_locate10},
/*SSC 0x2c*/{NULL},
/*SSC 0x2d*/{NULL},
/*SSC 0x2e*/{NULL},
/*SSC 0x2f*/{NULL},
/*SSC 0x30*/{NULL},
/*SSC 0x31*/{NULL},
/*SSC 0x32*/{NULL},
/*SSC 0x33*/{NULL},
/*SSC 0x34*/{dissect_ssc2_readposition},
/*SSC 0x35*/{NULL},
/*SSC 0x36*/{NULL},
/*SSC 0x37*/{NULL},
/*SSC 0x38*/{NULL},
/*SSC 0x39*/{NULL},
/*SSC 0x3a*/{NULL},
/*SPC 0x3b*/{dissect_spc3_writebuffer},
/*SSC 0x3c*/{NULL},
/*SSC 0x3d*/{NULL},
/*SSC 0x3e*/{NULL},
/*SSC 0x3f*/{NULL},
/*SSC 0x40*/{NULL},
/*SSC 0x41*/{NULL},
/*SSC 0x42*/{NULL},
/*SSC 0x43*/{NULL},
/*SSC 0x44*/{NULL},
/*SSC 0x45*/{NULL},
/*SSC 0x46*/{NULL},
/*SSC 0x47*/{NULL},
/*SSC 0x48*/{NULL},
/*SSC 0x49*/{NULL},
/*SSC 0x4a*/{NULL},
/*SSC 0x4b*/{NULL},
/*SPC 0x4c*/{dissect_spc3_logselect},
/*SPC 0x4d*/{dissect_spc3_logsense},
/*SSC 0x4e*/{NULL},
/*SSC 0x4f*/{NULL},
/*SSC 0x50*/{NULL},
/*SSC 0x51*/{NULL},
/*SSC 0x52*/{NULL},
/*SSC 0x53*/{NULL},
/*SSC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc3_modeselect10},
/*SSC 0x56*/{NULL},
/*SSC 0x57*/{NULL},
/*SSC 0x58*/{NULL},
/*SSC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc3_modesense10},
/*SSC 0x5b*/{NULL},
/*SSC 0x5c*/{NULL},
/*SSC 0x5d*/{NULL},
/*SPC 0x5e*/{dissect_spc3_persistentreservein},
/*SPC 0x5f*/{dissect_spc3_persistentreserveout},
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
/*SSC 0x80*/{NULL},
/*SSC 0x81*/{NULL},
/*SSC 0x82*/{NULL},
/*SPC 0x83*/{dissect_spc3_extcopy},
/*SSC 0x84*/{NULL},
/*SSC 0x85*/{NULL},
/*SSC 0x86*/{NULL},
/*SSC 0x87*/{NULL},
/*SSC 0x88*/{NULL},
/*SSC 0x89*/{NULL},
/*SSC 0x8a*/{NULL},
/*SSC 0x8b*/{NULL},
/*SSC 0x8c*/{NULL},
/*SSC 0x8d*/{NULL},
/*SSC 0x8e*/{NULL},
/*SSC 0x8f*/{NULL},
/*SSC 0x90*/{NULL},
/*SSC 0x91*/{dissect_ssc2_space16},
/*SSC 0x92*/{dissect_ssc2_locate16},
/*SSC 0x93*/{dissect_ssc2_erase16},
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
/*SPC 0xa0*/{dissect_spc3_reportluns},
/*SSC 0xa1*/{NULL},
/*SSC 0xa2*/{NULL},
/*SSC 0xa3*/{NULL},
/*SSC 0xa4*/{NULL},
/*SSC 0xa5*/{dissect_smc2_movemedium},
/*SSC 0xa6*/{NULL},
/*SSC 0xa7*/{dissect_smc2_movemedium},
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
/*SSC 0xb4*/{dissect_smc2_readelementstatus},
/*SSC 0xb5*/{NULL},
/*SSC 0xb6*/{NULL},
/*SSC 0xb7*/{NULL},
/*SSC 0xb8*/{dissect_smc2_readelementstatus},
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
           VALS (scsi_ssc_vals), 0x0, "", HFILL}},
        { &hf_scsi_ssc_rdwr6_xferlen,
          {"Transfer Length", "scsi.ssc.rdwr6.xferlen", FT_UINT24, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_ssc_locate10_loid,
          {"Logical Object Identifier", "scsi.ssc.locate10.loid", FT_UINT32, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_ssc_locate16_loid,
          {"Logical Identifier", "scsi.ssc.locate16.loid", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_ssc_space6_count,
          {"Count", "scsi.ssc.space6.count", FT_INT24, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_ssc_space16_count,
          {"Count", "scsi.ssc.space16.count", FT_UINT64, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_scsi_ssc_rdwr10_xferlen,
          {"Transfer Length", "scsi.ssc.rdwr10.xferlen", FT_UINT16, BASE_DEC, NULL,
           0x0, "", HFILL}},
	};


	/* Setup protocol subtree array */
/*
	static gint *ett[] = {
	};
*/

	/* Register the protocol name and description */
	proto_scsi_ssc = proto_register_protocol("SCSI_SSC", "SCSI_SSC", "scsi_ssc");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_scsi_ssc, hf, array_length(hf));
/*
	proto_register_subtree_array(ett, array_length(ett));
*/
}

void
proto_reg_handoff_scsi_ssc(void)
{
}

