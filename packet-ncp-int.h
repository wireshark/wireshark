/* packet-ncp-int.h
 * Structures and functions for NetWare Core Protocol.
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-ncp-int.h,v 1.6 2002/01/10 04:44:34 gram Exp $
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

typedef struct _ptvc_record ptvc_record;
typedef struct _sub_ptvc_record sub_ptvc_record;

struct _ptvc_record {
	int			*hf_ptr;
	gint			length;
	gboolean		endianness;
	const sub_ptvc_record	*sub_ptvc_rec;
};

struct _sub_ptvc_record {
	gint			*ett;
	const ptvc_record	*ptvc_rec;
};

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
		const ncp_record *ncp_rec);

const ncp_record* ncp_hash_lookup(conversation_t*, guint8 nw_sequence);


extern int proto_ncp;

#endif
