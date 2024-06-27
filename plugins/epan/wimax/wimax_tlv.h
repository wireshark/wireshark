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
	uint8_t  valid;          /* TLV info status: 0=invalid; 1=valid */
	uint8_t  type;           /* TLV type */
	uint8_t  length_type;    /* length type: 0=single byte; 1=multiple bytes */
	uint8_t  size_of_length; /* size of the TLV length */
	unsigned value_offset;   /* the offset of TLV value field */
	int32_t  length;         /* length of TLV value field */
} tlv_info_t;

int    init_tlv_info(tlv_info_t *info, tvbuff_t *tvb, int offset);
int    valid_tlv_info(tlv_info_t *info);
int    get_tlv_type(tlv_info_t *info);
int    get_tlv_length_type(tlv_info_t *info);
int    get_tlv_size_of_length(tlv_info_t *info);
int    get_tlv_value_offset(tlv_info_t *info);
int32_t get_tlv_length(tlv_info_t *info);
proto_item *add_tlv_subtree(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, const unsigned encoding);
proto_tree *add_tlv_subtree_no_item(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start);
proto_tree *add_protocol_subtree(tlv_info_t *info, int idx, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, const char *label);

#endif /* WIMAX_TLV_H */
