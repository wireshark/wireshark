/* packet-smb-pipe.h
 * Declarations of routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb-pipe.h,v 1.1 2001/03/18 03:23:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

gboolean
dissect_pipe_lanman(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si,
	int max_data, int SMB_offset, int errcode, int dirn,
	const u_char *command, int DataOffset, int DataCount,
	int ParameterOffset, int ParameterCount);

gboolean
dissect_pipe_smb(const u_char *pd, int offset, frame_data *fd,
    proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
    int SMB_offset, int errcode, int dirn, const u_char *command,
    int DataOffset, int DataCount, int ParameterOffset, int ParameterCount);
