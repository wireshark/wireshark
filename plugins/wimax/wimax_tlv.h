/* wimax_tlv.h
 * WiMax TLV handling function header file
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef _WIMAX_TLV_H_
#define _WIMAX_TLV_H_

#include <epan/packet.h>

#define	WIMAX_TLV_EXTENDED_LENGTH_MASK 0x80
#define	WIMAX_TLV_LENGTH_MASK          0x7F

#define MAX_TLV_LEN 64000

typedef struct
{
	guint8   valid;          /* TLV info status: 0=invalid; 1=valid */
	guint8   type;           /* TLV type */
	guint8   length_type;    /* length type: 0=single byte; 1=multiple bytes */
	guint8   size_of_length; /* size of the TLV length */
	guint    value_offset;   /* the offset of TLV value field */
	gint32   length;         /* length of TLV value field */
} tlv_info_t;

gint   init_tlv_info(tlv_info_t *info, tvbuff_t *tvb, gint offset);
gint   valid_tlv_info(tlv_info_t *info);
gint   get_tlv_type(tlv_info_t *info);
gint   get_tlv_length_type(tlv_info_t *info);
gint   get_tlv_size_of_length(tlv_info_t *info);
gint   get_tlv_value_offset(tlv_info_t *info);
gint32 get_tlv_length(tlv_info_t *info);
proto_item *add_tlv_subtree(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, const guint encoding);
proto_tree *add_tlv_subtree_no_item(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start);
proto_tree *add_protocol_subtree(tlv_info_t *info, gint idx, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char *label);

#endif /* WIMAX_TLV_H */
