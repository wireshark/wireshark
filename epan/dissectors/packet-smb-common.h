/* packet-smb-common.h
 * Routines for SMB packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#ifndef __PACKET_SMB_COMMON_H__
#define __PACKET_SMB_COMMON_H__

#include "smb.h"

int dissect_smb_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

int display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data);

int display_ms_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data);

const gchar *get_unicode_or_ascii_string(tvbuff_t *tvb, int *offsetp,
    gboolean useunicode, int *len, gboolean nopad, gboolean exactlen,
    guint16 *bcp);

int dissect_smb_64bit_time(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_date);

int dissect_nt_sid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, 
		   char *name, char **sid_str, int hf_sid);

/* 
 * Stuff for dissecting NT access masks 
 */

typedef void (nt_access_mask_fn_t)(tvbuff_t *tvb, gint offset,
				   proto_tree *tree, guint32 access);

/* Map generic access permissions to specific permissions */

struct generic_mapping {
	guint32 generic_read;
	guint32 generic_write;
	guint32 generic_execute;
	guint32 generic_all;
};

/* Map standard access permissions to specific permissions */

struct standard_mapping {
	guint32 std_read;
	guint32 std_write;
	guint32 std_execute;
	guint32 std_all;
};

struct access_mask_info {
	char *specific_rights_name;
	nt_access_mask_fn_t *specific_rights_fn;
	struct generic_mapping *generic_mapping;
	struct standard_mapping *standard_mapping;
};

int
dissect_nt_access_mask(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, guint8 *drep, int hfindex,
		       struct access_mask_info *ami,
		       guint32 *perms);

int
dissect_nt_sec_desc(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *parent_tree, guint8 *drep, int len, 
		    struct access_mask_info *ami);

extern const value_string share_type_vals[];

#endif
