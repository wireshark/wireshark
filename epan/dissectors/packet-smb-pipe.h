/* packet-smb-pipe.h
 * Declarations of routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _PACKET_SMB_PIPE_H_
#define _PACKET_SMB_PIPE_H_

extern gboolean
dissect_pipe_smb(tvbuff_t *sp_tvb, tvbuff_t *s_tvb, tvbuff_t *pd_tvb,
		 tvbuff_t *p_tvb, tvbuff_t *d_tvb, const char *pipe,
		 packet_info *pinfo, proto_tree *tree, smb_info_t *smb_info);
gboolean
dissect_pipe_dcerpc(tvbuff_t *d_tvb, packet_info *pinfo, proto_tree *parent_tree,
		proto_tree *tree, guint32 fid);

#endif
