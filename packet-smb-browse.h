/* packet-smb-browse.h
 * Declaration of routines for SMB Browser packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb-browse.h,v 1.3 2001/08/01 03:47:00 guy Exp $
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

#ifndef _PACKET_SMB_BROWSE_H_
#define _PACKET_SMB_BROWSE_H_

gboolean
dissect_mailslot_browse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

gboolean
dissect_mailslot_lanman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

#endif
