/* packet-smb2.h
 * Defines for SMB2 packet dissection
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998, 1999 Gerald Combs
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

#ifndef __PACKET_SMB2_H__
#define __PACKET_SMB2_H__

/* SMB2 command codes. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string smb2_cmd_vals[];

typedef struct _smb2_saved_info_t {
	guint8 class;
	guint8 infolevel;
	guint64 seqnum;
	char *create_name;
	gboolean response; /* is this a response ? */
	guint32 frame_req, frame_res;
	nstime_t req_time;
} smb2_saved_info_t;

/* structure to keep track of conversations and the hash tables. */
typedef struct _smb2_info_t {
	/* these two tables are used to match requests with responses */
	GHashTable *unmatched;
	GHashTable *matched;
} smb2_info_t;

#endif
