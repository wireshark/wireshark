/* packet-llc.c
 * Routines for IEEE 802.2 LLC layer
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-llc.c,v 1.12 1999/03/22 03:44:44 guy Exp $
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


#include <gtk/gtk.h>

#include <stdio.h>

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"

typedef void (capture_func_t)(const u_char *, int, guint32, packet_counts *);
typedef void (dissect_func_t)(const u_char *, int, frame_data *, GtkTree *);

struct sap_info {
	guint8	sap;
	capture_func_t *capture_func;
	dissect_func_t *dissect_func;
	char	*text;
};

static struct sap_info	saps[] = {
	{ 0x00, NULL,		NULL,		"NULL LSAP" },
	{ 0x02, NULL,		NULL,		"LLC Sub-Layer Management Individual" },
	{ 0x03, NULL,		NULL,		"LLC Sub-Layer Management Group" },
	{ 0x04, NULL,		NULL,		"SNA Path Control Individual" },
	{ 0x05, NULL,		NULL,		"SNA Path Control Group" },
	{ 0x06, capture_ip,	dissect_ip,	"TCP/IP" },
	{ 0x08, NULL,		NULL,		"SNA" },
	{ 0x0C, NULL,		NULL,		"SNA" },
	{ 0x42, NULL,		NULL,		"Spanning Tree BPDU" },
	{ 0x7F, NULL,		NULL,		"ISO 802.2" },
	{ 0x80, NULL,		NULL,		"XNS" },
	{ 0xAA, NULL,		NULL,		"SNAP" },
	/*{ 0xBA, NULL,		dissect_vines,	"Banyan Vines" },
	{ 0xBC, NULL,		dissect_vines,	"Banyan Vines" },*/
	{ 0xBA, NULL,		NULL,		"Banyan Vines" },
	{ 0xBC, NULL,		NULL,		"Banyan Vines" },
	{ 0xE0, NULL,		dissect_ipx,	"NetWare" },
	{ 0xF0, NULL,		NULL,		"NetBIOS" },
	{ 0xF4, NULL,		NULL,		"IBM Net Management Individual" },
	{ 0xF5, NULL,		NULL,		"IBM Net Management Group" },
	{ 0xF8, NULL,		NULL,		"Remote Program Load" },
	{ 0xFC, NULL,		NULL,		"Remote Program Load" },
	{ 0xFE, NULL,		dissect_osi,	"ISO Network Layer" },
	{ 0xFF, NULL,		NULL,		"Global LSAP" },
	{ 0x00, NULL,		NULL,		NULL }
};


static char*
sap_text(u_char sap) {
	int i=0;

	while (saps[i].text != NULL) {
		if (saps[i].sap == sap) {
			return saps[i].text;
		}
		i++;
	}
	return "Unknown";
}

static capture_func_t *
sap_capture_func(u_char sap) {
	int i=0;

	while (saps[i].text != NULL) {
		if (saps[i].sap == sap) {
			return saps[i].capture_func;
		}
		i++;
	}
	return capture_data;
}

static dissect_func_t *
sap_dissect_func(u_char sap) {
	int i=0;

	while (saps[i].text != NULL) {
		if (saps[i].sap == sap) {
			return saps[i].dissect_func;
		}
		i++;
	}
	return dissect_data;
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
dissect_llc(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*llc_tree = NULL, *ti;
	guint16		etype;
	int		is_snap;
	dissect_func_t	*dissect;

	/* LLC Strings */
	char *llc_ctrl[4] = {
		"Information Transfer", "Supervisory",
		"", "Unnumbered Information" };

	is_snap = (pd[offset] == 0xAA) && (pd[offset+1] == 0xAA);

	if (check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd, COL_PROTOCOL, "LLC");
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
		if (check_col(fd, COL_INFO)) {
			col_add_str(fd, COL_INFO, "802.2 LLC (SNAP)");
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
		if (check_col(fd, COL_INFO)) {
			col_add_fstr(fd, COL_INFO, "802.2 LLC (%s)", sap_text(pd[offset]));
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
