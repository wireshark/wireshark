/* packet-rmt-common.h
 * Reliable Multicast Transport (RMT)
 * Common RMT function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#ifndef __PACKET_RMT_COMMON__
#define __PACKET_RMT_COMMON__

/* Boolean string tables external references */
extern const true_false_string boolean_set_notset;
extern const true_false_string boolean_yes_no;

/* Type definitions */
/* ================ */

/* Logical header extension representation */
struct _ext
{
	guint offset;
	guint length;
	
	guint8 het;
	guint8 hel;
	
	guint hec_offset;
	guint8 hec_size;
};

/* Common RMT exported functions */
/* ============================= */

void rmt_ext_parse(GArray *a, tvbuff_t *tvb, guint *offset, guint offset_max);

void rmt_ext_decode_default(struct _ext *e, tvbuff_t *tvb, proto_tree *tree, gint ett);
void rmt_ext_decode_default_subtree(struct _ext *e, tvbuff_t *tvb, proto_tree *tree, gint ett);
void rmt_ext_decode_default_header(struct _ext *e, tvbuff_t *tvb, proto_tree *tree);

#endif
