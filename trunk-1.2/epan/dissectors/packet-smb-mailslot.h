/* packet-smb-mailslot.h
 * Declaration of routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _PACKET_SMB_MAILSLOT_H_
#define _PACKET_SMB_MAILSLOT_H_

gboolean
dissect_mailslot_smb(tvbuff_t *total_tvb, tvbuff_t *setup_tvb,
		     tvbuff_t *tvb, const char *mailslot,
		     packet_info *pinfo, proto_tree *tree);

#endif
