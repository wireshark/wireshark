/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gramirez@tivoli.com>
 *
 * $Id: packet-llc.c,v 1.15 1999/07/07 22:51:46 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"
	
int proto_llc = -1;
int hf_llc_dsap = -1;
int hf_llc_ssap = -1;
int hf_llc_ctrl = -1;
int hf_llc_type = -1;
int hf_llc_oui = -1;

typedef void (capture_func_t)(const u_char *, int, guint32, packet_counts *);
typedef void (dissect_func_t)(const u_char *, int, frame_data *, proto_tree *);

/* The SAP info is split into two tables, one value_string table and one table of sap_info. This is
 * so that the value_string can be used in the header field registration.
 */
struct sap_info {
	guint8	sap;
	capture_func_t *capture_func;
	dissect_func_t *dissect_func;
};

static const value_string sap_vals[] = {
	{ 0x00, "NULL LSAP" },
	{ 0x02, "LLC Sub-Layer Management Individual" },
	{ 0x03, "LLC Sub-Layer Management Group" },
	{ 0x04, "SNA Path Control Individual" },
	{ 0x05, "SNA Path Control Group" },
	{ 0x06, "TCP/IP" },
	{ 0x08, "SNA" },
	{ 0x0C, "SNA" },
	{ 0x42, "Spanning Tree BPDU" },
	{ 0x7F, "ISO 802.2" },
	{ 0x80, "XNS" },
	{ 0xAA, "SNAP" },
	{ 0xBA, "Banyan Vines" },
	{ 0xBC, "Banyan Vines" },
	{ 0xE0, "NetWare" },
	{ 0xF0, "NetBIOS" },
	{ 0xF4, "IBM Net Management Individual" },
	{ 0xF5, "IBM Net Management Group" },
	{ 0xF8, "Remote Program Load" },
	{ 0xFC, "Remote Program Load" },
	{ 0xFE, "ISO Network Layer" },
	{ 0xFF, "Global LSAP" },
	{ 0x00, NULL }
};

static struct sap_info	saps[] = {
	{ 0x00, NULL,		NULL },
	{ 0x02, NULL,		NULL },
	{ 0x03, NULL,		NULL },
	{ 0x04, NULL,		NULL },
	{ 0x05, NULL,		NULL },
	{ 0x06, capture_ip,	dissect_ip },
	{ 0x08, NULL,		NULL },
	{ 0x0C, NULL,		NULL },
	{ 0x42, NULL,		NULL },
	{ 0x7F, NULL,		NULL },
	{ 0x80, NULL,		NULL },
	{ 0xAA, NULL,		NULL },
	{ 0xBA, NULL,		NULL },
	{ 0xBC, NULL,		NULL },
	{ 0xE0, NULL,		dissect_ipx },
	{ 0xF0, NULL,		NULL },
	{ 0xF4, NULL,		NULL },
	{ 0xF5, NULL,		NULL },
	{ 0xF8, NULL,		NULL },
	{ 0xFC, NULL,		NULL },
	{ 0xFE, NULL,		dissect_osi },
	{ 0xFF, NULL,		NULL },
	{ 0x00, NULL,		NULL}
};

static const value_string llc_ctrl_vals[] = {
	{ 0, "Information Transfer" },
	{ 1, "Supervisory" },
	{ 2, "Unknown" },
	{ 3, "Unnumbered Information" },
	{ 0, NULL }
};

static const value_string llc_oui_vals[] = {
	{ 0x000000, "Encapsulated Ethernet" },
/*
http://www.cisco.com/univercd/cc/td/doc/product/software/ios113ed/113ed_cr/ibm_r/brprt1/brsrb.htm
*/
	{ 0x0000f8, "Cisco 90-Compatible" },
	{ 0x0000c0, "Cisco" },
	{ 0x0080c2, "Bridged Frame-Relay" }, /* RFC 2427 */
	{ 0,        NULL }
};

static capture_func_t *
sap_capture_func(u_char sap) {
	int i=0;

	/* look for the second record where sap == 0, which should
	 * be the last record
	 */
	while (saps[i].sap > 0 || i == 0) {
		if (saps[i].sap == sap) {
			return saps[i].capture_func;
		}
		i++;
	}
	return NULL;
}

static dissect_func_t *
sap_dissect_func(u_char sap) {
	int i=0;

	/* look for the second record where sap == 0, which should
	 * be the last record
	 */
	while (saps[i].sap > 0 || i == 0) {
		if (saps[i].sap == sap) {
			return saps[i].dissect_func;
		}
		i++;
	}
	return dissect_data;
}


void
capture_llc(const u_char *pd, int offset, guint32 cap_len, packet_counts *ld) {

	guint16		etype;
	int		is_snap;
	capture_func_t	*capture;

	is_snap = (pd[offset] == 0xAA) && (pd[offset+1] == 0xAA);
	if (is_snap) {
		etype  = (pd[offset+6] << 8) | pd[offset+7];
		offset += 8;
		capture_ethertype(etype, offset, pd, cap_len, ld);
	}		
	else {
		capture = sap_capture_func(pd[offset]);

		/* non-SNAP */
		offset += 3;

		if (capture) {
			capture(pd, offset, cap_len, ld);
		}
		else {
			ld->other++;
		}

	}
}

void
dissect_llc(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*llc_tree = NULL;
	proto_item	*ti;
	guint16		etype;
	int		is_snap;
	dissect_func_t	*dissect;

	is_snap = (pd[offset] == 0xAA) && (pd[offset+1] == 0xAA);

	if (check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd, COL_PROTOCOL, "LLC");
	}
  
	if (tree) {
		ti = proto_tree_add_item(tree, proto_llc, offset, (is_snap ? 8 : 3), NULL);
		llc_tree = proto_item_add_subtree(ti, ETT_LLC);
		proto_tree_add_item(llc_tree, hf_llc_dsap, offset, 1, pd[offset]);
		proto_tree_add_item(llc_tree, hf_llc_ssap, offset+1, 1, pd[offset+1]);
		proto_tree_add_item(llc_tree, hf_llc_ctrl, offset+2, 1, pd[offset+2] & 3);
	}

	if (is_snap) {
		if (check_col(fd, COL_INFO)) {
			col_add_str(fd, COL_INFO, "802.2 LLC (SNAP)");
		}
		if (tree) {
			proto_tree_add_item(llc_tree, hf_llc_oui, offset+3, 3,
				pd[offset+3] << 16 | pd[offset+4] << 8 | pd[offset+5]);
		}
		etype = pntohs(&pd[offset+6]);
		offset += 8;
		/* w/o even checking, assume OUI is ethertype */
		ethertype(etype, offset, pd, fd, tree, llc_tree, hf_llc_type);
	}		
	else {
		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO, "802.2 LLC (%s)",
				val_to_str(pd[offset], sap_vals, "%02x"));
		}

		dissect = sap_dissect_func(pd[offset]);

		/* non-SNAP */
		offset += 3;

		if (dissect) {
			dissect(pd, offset, fd, tree);
		}
		else {
			dissect_data(pd, offset, fd, tree);
		}

	}
}

void
proto_register_llc(void)
{
	const hf_register_info hf[] = {
		{ "DSAP",		"llc.dsap", &hf_llc_dsap, FT_VALS_UINT8, VALS(sap_vals) },
		{ "SSAP",		"llc.ssap", &hf_llc_ssap, FT_VALS_UINT8, VALS(sap_vals) },
		{ "Control",		"llc.control", &hf_llc_ctrl, FT_VALS_UINT8, VALS(llc_ctrl_vals) },

		/* registered here but handled in ethertype.c */	
		{ "Type",		"llc.type", &hf_llc_type, FT_VALS_UINT16, VALS(etype_vals) },

		{ "Organization Code",	"llc.oui", &hf_llc_oui, FT_VALS_UINT24, VALS(llc_oui_vals) }
	};

	proto_llc = proto_register_protocol ("Logical-Link Control", "llc" );
	proto_register_field_array(proto_llc, hf, array_length(hf));
}
