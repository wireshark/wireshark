/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-llc.c,v 1.2 1998/09/16 03:22:06 gerald Exp $
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

#include <pcap.h>

#include <gtk/gtk.h>

#include <stdio.h>

#include "packet.h"
#include "ethereal.h"
#include "etypes.h"

struct sap_info {
	u_char	sap;
	char	*text;
};

static char*
sap_text(u_char sap) {
	int i=0;

	static struct sap_info	saps[] = {
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

	while (saps[i].text != NULL) {
		if (saps[i].sap == sap) {
			return saps[i].text;
		}
		i++;
	}
	return "Unknown";
}

static char*
llc_org(const u_char *ptr) {

	unsigned long org = (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
	char *llc_org[1] = {
		"Encapsulated Ethernet"};

	if (org > 0) {
		return "Unknown";
	}
	else {
		return llc_org[org];
	}
}

void
dissect_llc(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*llc_tree, *ti;
	guint16		etype;
	int			is_snap;

	/* LLC Strings */
	char *llc_ctrl[4] = {
		"Information Transfer", "Supervisory",
		"", "Unnumbered Information" };

	is_snap = (pd[offset] == 0xAA) && (pd[offset+1] == 0xAA);

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "LLC");
	}
  
	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, (is_snap ? 8 : 3),
			"Logical-Link Control");
		llc_tree = gtk_tree_new();
		add_subtree(ti, llc_tree, ETT_LLC);
		add_item_to_tree(llc_tree, offset,      1, "DSAP: %s (0x%02X)",
			sap_text(pd[offset]), pd[offset]);
		add_item_to_tree(llc_tree, offset+1,    1, "SSAP: %s (0x%02X)",
			sap_text(pd[offset+1]), pd[offset+1]);
		add_item_to_tree(llc_tree, offset+2,    1, "Control: %s",
			llc_ctrl[pd[offset+2] & 3]);
	}

	if (is_snap) {
		if (fd->win_info[0]) {
			strcpy(fd->win_info[4], "802.2 LLC (SNAP)");
		}
		if (tree) {
			add_item_to_tree(llc_tree, offset+3,    3,
				"Organization Code: %s (%02X-%02X-%02X)",
				llc_org(&pd[offset+3]), 
				pd[offset+3], pd[offset+4], pd[offset+5]);
		}
		etype  = (pd[offset+6] << 8) | pd[offset+7];
		offset += 8;
		ethertype(etype, offset, pd, fd, tree, llc_tree);
	}		
	else {
		if (fd->win_info[0]) {
			sprintf(fd->win_info[4], "802.2 LLC (%s)", sap_text(pd[offset]));
		}

		/* non-SNAP */
		offset += 3;

		switch (pd[offset-3]) {
			case 0x06:	/* TCP/IP */
				dissect_ip(pd, offset, fd, tree);
				break;
			case 0xe0:	/* NetWare (IPX) */
				dissect_ipx(pd, offset, fd, tree);
				break;
			default:
				dissect_data(pd, offset, fd, tree);
				break;
		  }
	}
}
