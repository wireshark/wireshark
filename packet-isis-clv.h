/* packet-isis-clv.h
 * Declares for common clv decoding functions.
 *
 * $Id: packet-isis-clv.h,v 1.3 2001/04/08 19:32:03 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
 *
 *
 */
#ifndef _PACKET_ISIS_CLV_H
#define _PACKET_ISIS_CLV_H

/*
 * Our sub-packet dismantle structure for CLV's
 */
typedef struct {
	int	optcode;		/* code for option */
	char	*tree_text;		/* text for fold out */
	gint	*tree_id;		/* id for add_item */
	void	(*dissect)(const u_char *pd, int offset, guint length,
			int id_length, frame_data *fd, proto_tree *tree );
} isis_clv_handle_t;

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_clvs(const isis_clv_handle_t *opts, int len,
	int id_length, const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, int unknown_ett_handle );
extern void isis_dissect_area_address_clv(const u_char *pd, int offset,
                guint length, frame_data *fd, proto_tree *tree );
extern void isis_dissect_metric(proto_tree *tree, int offset, guint8 value,
                char *pstr, int force_supported, gint tree_id );
extern void isis_dissect_authentication_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree, char *meaning);
extern void isis_dissect_ip_int_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree, gint tree_id );
extern void isis_dissect_nlpid_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree );
extern void isis_dissect_hostname_clv(const u_char *pd, int offset, 
                guint length, frame_data *fd, proto_tree *tree );
#endif /* _PACKET_ISIS_CLV_H */
