/* packet-smb-mailslot.h
 * Declaration of routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-mailslot.h,v 1.2 2001/08/05 00:16:36 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

gboolean
dissect_mailslot_smb(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, const u_char *command,
	int DataOffset, int DataCount, int ParameterOffset, int ParameterCount);
