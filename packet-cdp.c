/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.14 1999/09/17 05:56:53 guy Exp $
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
 */
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "packet.h"

/* Offsets in TLV structure. */
#define	TLV_TYPE	0
#define	TLV_LENGTH	2

static int proto_cdp = -1;
static int hf_cdp_tlvtype = -1;
static int hf_cdp_tlvlength = -1;

static void
add_multi_line_string_to_tree(proto_tree *tree, gint start, gint len,
  const gchar *prefix, const gchar *string);

#define TYPE_MGMT_ADDR		0
#define TYPE_CHASSIS_ID		1
#define TYPE_2			2
#define TYPE_PORT		3
#define TYPE_IOS_VERSION	5
#define TYPE_PLATFORM		6
#define TYPE_MGMT_IP_ADDR	0x01cc

static const value_string type_vals[] = {
	{ TYPE_MGMT_ADDR,    "Mgmt addr?" },
	{ TYPE_CHASSIS_ID,   "Chassis ID" },
	{ TYPE_2,            "Unknown" },
	{ TYPE_PORT,         "Port" },
	{ TYPE_IOS_VERSION,  "Software version" },
	{ TYPE_PLATFORM,     "Platform" },
	{ TYPE_MGMT_IP_ADDR, "Mgmt IP" },
	{ 0,                 NULL },
};
	
void 
dissect_cdp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    proto_item *ti; 
    proto_tree *cdp_tree = NULL;
    guint16 type;
    guint16 length;
    char *type_str;
    char *stringmem;
    proto_item *tlvi;
    proto_tree *tlv_tree;

    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "CDP");
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, "Cisco Discovery Protocol"); 

    if(tree){
        ti = proto_tree_add_item(tree, proto_cdp, offset, END_OF_FRAME, NULL);
	cdp_tree = proto_item_add_subtree(ti, ETT_CDP);
	
	/* CDP header */
	proto_tree_add_text(cdp_tree, offset, 1, "Version: %u", pd[offset]);
	offset += 1;
	proto_tree_add_text(cdp_tree, offset, 1, "Flags: %x (unknown)",
	    pd[offset]);
	offset += 1;
	proto_tree_add_text(cdp_tree, offset, 2, "TTL: %u (unknown)",
	    pntohs(&pd[offset]));
	offset += 2;

	while( IS_DATA_IN_FRAME(offset) ){
		type = pntohs(&pd[offset + TLV_TYPE]);
		length = pntohs(&pd[offset + TLV_LENGTH]);
		type_str = val_to_str(type, type_vals,
		    "Unknown (0x%04x)");

		switch( type ){
			case TYPE_MGMT_ADDR:
				/* ??? Mgmt Addr; in this one, the "length"
				   field doesn't include the length of the
				   type and length fields. */
				tlvi = proto_tree_add_text(cdp_tree, offset,
				    length + 4, "Type: %s, length: %u",
				    type_str, length);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				if (length > 0) {
					proto_tree_add_text(tlv_tree,
					    offset + 4, length, "Data");
				}
				offset+=length + 4;
				break;
			case TYPE_CHASSIS_ID:
				/* ??? Chassis ID */
				tlvi = proto_tree_add_text(cdp_tree, offset,
				    length, "Chassis ID: %s",
				    &pd[offset+4]);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, offset + 4,
				    length - 4, "Chassis ID: %s",
				    &pd[offset+4]);
				offset+=length;
				break;
			case TYPE_2:
				/* this is quite strange: this tlv contains
				   no data itself but two tlvs which
				   calculate the length without the 2 byte
				   type and 2 byte length field */
				tlvi = proto_tree_add_text(cdp_tree, offset,
				    4, "Type: %u (unknown), second field: %u",
				    type, length);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_text(tlv_tree,
				    offset + TLV_LENGTH, 2, "Second field: %u",
				    length);
				offset+=4;
				break;
			case TYPE_PORT:
				/* ??? Port  */    
				tlvi = proto_tree_add_text(cdp_tree, offset,
				    length, "Sent through Interface: %s",
				    &pd[offset+4]);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, offset + 4,
				    length - 4, "Sent through Interface: %s",
				    &pd[offset+4]);
				offset+=length;
				break;
			case TYPE_IOS_VERSION:
				/* ??? IOS Version */
				add_multi_line_string_to_tree(cdp_tree,
				    offset + 4, length - 4, "Software Version: ",
				    &pd[offset+4] );
				offset+=length;
				break;
			case TYPE_PLATFORM:
				/* ??? platform */
				stringmem = malloc(length);
				memset(stringmem, '\0', length);
				memcpy(stringmem, &pd[offset+4], length - 4 );
				tlvi = proto_tree_add_text(cdp_tree,
				    offset, length, "Platform: %s",
				    stringmem);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, offset + 4,
				    length - 4, "Platform: %s", stringmem);
				free(stringmem);
				offset+=length;
				break;
			case TYPE_MGMT_IP_ADDR:
				/* ??? Mgmt IP Addr; in this one, the "length"
				   field doesn't include the length of the
				   type and length fields. */
				tlvi = proto_tree_add_text(cdp_tree,
				    offset, length + 4, "Mgmt IP: %s",
				    ip_to_str(&pd[offset+4]));
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, offset + 4,
				    length, "IP address: %s",
				    ip_to_str(&pd[offset+4]));
				offset+=length + 4;
				break;
			default:
				tlvi = proto_tree_add_text(cdp_tree, offset,
				    length, "Type: %s, length: %u",
				    type_str, length);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ETT_CDP_TLV);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvtype,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_item(tlv_tree, hf_cdp_tlvlength,
				    offset + TLV_LENGTH, 2, length);
				if (length > 4) {
					proto_tree_add_text(tlv_tree,
					    offset + 4, length - 4, "Data");
				} else
					return;
				offset+=length;
		}
	}
    	dissect_data(pd, offset, fd, cdp_tree);
    }
}

static void
add_multi_line_string_to_tree(proto_tree *tree, gint start, gint len,
  const gchar *prefix, const gchar *string)
{
    int prefix_len;
    int i;
    char blanks[64+1];
    const gchar *p, *q;
    int line_len;
    int data_len;

    prefix_len = strlen(prefix);
    if (prefix_len > 64)
	prefix_len = 64;
    for (i = 0; i < prefix_len; i++)
	blanks[i] = ' ';
    blanks[i] = '\0';
    p = string;
    for (;;) {
	q = strchr(p, '\n');
	if (q != NULL) {
	    line_len = q - p;
	    data_len = line_len + 1;
	} else {
	    line_len = strlen(p);
	    data_len = line_len;
	}
	proto_tree_add_text(tree, start, data_len, "%s%.*s", prefix,
	   line_len, p);
	if (q == NULL)
	    break;
	p += data_len;
	start += data_len;
	prefix = blanks;
    }
}

void
proto_register_cdp(void)
{
        static hf_register_info hf[] = {
                { &hf_cdp_tlvtype,
                { "Type",		"cdp.tlv.type", FT_VALS_UINT16, VALS(type_vals) }},

                { &hf_cdp_tlvlength,
                { "Length",		"cdp.tlv.len", FT_UINT16, NULL }},
        };

        proto_cdp = proto_register_protocol("Cisco Discovery Protocol", "cdp");
        proto_register_field_array(proto_cdp, hf, array_length(hf));
}
