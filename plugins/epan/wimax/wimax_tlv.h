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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
