/* packet-ncp-int.h
 * Structures and functions for NetWare Core Protocol.
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-ncp-int.h,v 1.3 2001/06/28 02:42:48 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000 Gerald Combs
 *
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

#ifndef __PACKET_NCP_INT_H__
#define __PACKET_NCP_INT_H__

typedef struct {
	int		*hf_ptr;
	gint		length;
	gboolean	endianness;
} ptvc_record;

typedef struct {
	guint8		error_in_packet;
	gint		ncp_error_index;
} error_equivalency;

typedef struct {
	guint8			func;
	guint8			subfunc;
	guint8			has_subfunc;
	gchar*			name;
	gint			group;
	const ptvc_record	*request_ptvc;
	void			*requst_func;
	const ptvc_record	*reply_ptvc;
	void			*reply_func;
	const error_equivalency	*errors;
} ncp_record;


void dissect_ncp_request(tvbuff_t*, packet_info*, guint16,
		guint8, guint16, proto_tree*, proto_tree*);

void dissect_ncp_reply(tvbuff_t *, packet_info*, guint16,
		guint8, proto_tree*, proto_tree*);

void ncp_hash_insert(conversation_t *conversation, guint8 nw_sequence,
		guint16 ncp_type, const ncp_record *ncp_rec);

/* Returns TRUE or FALSE. If TRUE, the record was found and
 * ncp_type and ncp_rec are set. */
gboolean ncp_hash_lookup(conversation_t*, guint8 nw_sequence,
		guint16 *ncp_type, const ncp_record **ncp_rec);


extern int proto_ncp;

#endif
