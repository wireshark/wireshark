/* packet-ncp-int.h
 * Structures and functions for NetWare Core Protocol.
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-ncp-int.h,v 1.6.2.9 2002/05/09 04:24:36 gram Exp $
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
	const sub_ptvc_record	*sub_ptvc_rec;
	unsigned int	endianness	: 1; /* 0=BE, 1=LE */
	unsigned int	var_index	: 2;
	unsigned int	repeat_index	: 2;
	unsigned int	req_cond_index	: 6;
	unsigned int	special_fmt	: 2;
};

#define NCP_FMT_NONE			0
#define NCP_FMT_NW_DATE			1
#define NCP_FMT_NW_TIME			2

struct _sub_ptvc_record {
	gint			*ett;
	const char		*descr;
	const ptvc_record	*ptvc_rec;
};

typedef struct {
	const char		*dfilter_text;
	dfilter_t		*dfilter;
} conditional_record;

typedef struct {
	int			*hf_ptr;
	const char		*first_string;
	const char		*repeat_string;
} info_string_t;

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
	const ptvc_record	*reply_ptvc;
	const error_equivalency	*errors;
	const int		*req_cond_indexes;
	unsigned int		req_cond_size_type;
	const info_string_t	*req_info_str;
} ncp_record;


void dissect_ncp_request(tvbuff_t*, packet_info*, guint16,
		guint8, guint16, proto_tree*, proto_tree*);

void dissect_ncp_reply(tvbuff_t *, packet_info*, guint16,
		guint8, proto_tree*, proto_tree*);

extern int proto_ncp;
extern gint ett_ncp;

#endif
