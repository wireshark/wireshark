/* rpc_defrag.h
 * Declarations for RPC defragmentation
 *
 * $Id$
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

#ifndef __RPC_DEFRAG_H__
#define __RPC_DEFRAG_H__

/*
 * RPC-over-TCP fragmentation.
 */
#define RPC_RM_LASTFRAG	0x80000000U
#define RPC_RM_FRAGLEN	0x7fffffffU

typedef gboolean (*rec_dissector_t)(tvbuff_t *, packet_info *, proto_tree *,
	tvbuff_t *, fragment_data *, gboolean, guint32, gboolean);

extern void show_rpc_fraginfo(tvbuff_t *tvb, tvbuff_t *frag_tvb,
	proto_tree *tree, guint32 rpc_rm, fragment_data *ipfd_head, packet_info *pinfo);
extern int dissect_rpc_fragment(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, rec_dissector_t dissector, gboolean is_heur,
	int proto, int ett, gboolean defragment, gboolean first_pdu);

#endif /* __RPC_DEFRAG_H__ */
