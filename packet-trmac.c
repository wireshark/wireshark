/* packet-trmac.c
 * Routines for Token-Ring Media Access Control
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-trmac.c,v 1.5 1998/10/21 02:36:54 gram Exp $
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

#include <pcap.h>

#include <gtk/gtk.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"

/* Major Vector */
static value_string major_vectors[] = {
		{ 0x00, "Response" },
		{ 0x02, "Beacon" },
		{ 0x03, "Claim Token" },
		{ 0x04, "Ring Purge" },
		{ 0x05, "Active Monitor Present" },
		{ 0x06, "Standby Monitor Present" },
		{ 0x07, "Duplicate Address Test" },
		{ 0x09, "Transmit Forward" },
		{ 0x0B, "Remove Ring Station" },
		{ 0x0C, "Change Parameters" },
		{ 0x0D, "Initialize Ring Station" },
		{ 0x0E, "Request Ring Station Address" },
		{ 0x0F, "Request Ring Station Address" },
		{ 0x10, "Request Ring Station Attachments" },
		{ 0x20, "Request Initialization" },
		{ 0x22, "Report Ring Station Address" },
		{ 0x23, "Report Ring Station State" },
		{ 0x24, "Report Ring Station Attachments" },
		{ 0x25, "Report New Active Monitor" },
		{ 0x26, "Report NAUN Change" },
		{ 0x27, "Report Poll Error" },
		{ 0x28, "Report Monitor Errors" },
		{ 0x29, "Report Error" },
		{ 0x2A, "Report Transmit Forward" },
		{ 0x00, NULL }
};


/* Sub-vectors */
static int
sv_text(const u_char *pd, int pkt_offset, GtkWidget *tree)
{
	int	sv_length = pd[0];

	char *beacon[] = {"Recovery mode set", "Signal loss error",
		"Streaming signal not Claim Token MAC frame",
		"Streaming signal, Claim Token MAC frame"};

	GtkWidget	*sv_tree, *ti;

	u_char		errors[6];	/* isolating or non-isolating */

	/* this just adds to the clutter on the screen...
	add_item_to_tree(tree, pkt_offset, 1,
		"Subvector Length: %d bytes", sv_length);*/

	switch(pd[1]) {
		case 0x01: /* Beacon Type */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Beacon Type: %s", beacon[ pntohs( &pd[2] ) ] );
			break;

		case 0x02: /* NAUN */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"NAUN: %s", ether_to_str((guint8*)&pd[2]));
			break;

		case 0x03: /* Local Ring Number */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Local Ring Number: 0x%04X (%d)",
				pntohs( &pd[2] ), pntohs( &pd[2] ));
			break;

		case 0x04: /* Assign Physical Location */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Assign Physical Location: 0x%08X", pntohl( &pd[2] ) );
			break;

		case 0x05: /* Soft Error Report Value */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Soft Error Report Value: %d ms", 10 * pntohs( &pd[2] ) );
			break;

		case 0x06: /* Enabled Function Classes */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Enabled Function Classes: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x07: /* Allowed Access Priority */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Allowed Access Priority: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x09: /* Correlator */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Correlator: %04X",  pntohs( &pd[2] ) );
			break;

		case 0x0A: /* Address of last neighbor notification */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Address of Last Neighbor Notification: %s",
				ether_to_str((guint8*)&pd[2]));
			break;

		case 0x0B: /* Physical Location */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Physical Location: 0x%08X", pntohl( &pd[2] ) );
			break;

		case 0x20: /* Response Code */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Response Code: 0x%04X 0x%04X", pntohl( &pd[2] ),
				pntohl( &pd[4] ) );
			break;

		case 0x21: /* Reserved */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Reserved: 0x%04X", pntohs( &pd[2] ) );
			break;

		case 0x22: /* Product Instance ID */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Product Instance ID: ...");
			break;

		case 0x23: /* Ring Station Microcode Level */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Ring Station Microcode Level: ...");
			break;

		case 0x26: /* Wrap data */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Wrap Data: ... (%d bytes)", sv_length - 2);
			break;

		case 0x27: /* Frame Forward */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Frame Forward: ... (%d bytes)", sv_length - 2);
			break;

		case 0x29: /* Ring Station Status Subvector */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Ring Station Status Subvector: ...");
			break;

		case 0x2A: /* Transmit Status Code */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Transmit Status Code: %04X", pntohs( &pd[2] ) );
			break;

		case 0x2B: /* Group Address */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Group Address: %08X", pntohl( &pd[2] ) );
			break;

		case 0x2C: /* Functional Address */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Functional Address: %08X", pntohl( &pd[2] ) );
			break;

		case 0x2D: /* Isolating Error Counts */
			memcpy(errors, &pd[2], 6);
			ti = add_item_to_tree(GTK_WIDGET(tree), pkt_offset+1, sv_length-1,
				"Isolating Error Counts (%d total)",
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_tree = gtk_tree_new();
			add_subtree(ti, sv_tree, ETT_TR_IERR_CNT);

			add_item_to_tree(sv_tree, pkt_offset+2, 1,
				"Line Errors: %d", errors[0]);
			add_item_to_tree(sv_tree, pkt_offset+3, 1,
				"Internal Errors: %d", errors[1]);
			add_item_to_tree(sv_tree, pkt_offset+4, 1,
				"Burst Errors: %d", errors[2]);
			add_item_to_tree(sv_tree, pkt_offset+5, 1,
				"A/C Errors: %d", errors[3]);
			add_item_to_tree(sv_tree, pkt_offset+6, 1,
				"Abort delimiter transmitted: %d", errors[4]);

			break;

		case 0x2E: /* Non-Isolating Error Counts */
			memcpy(errors, &pd[2], 6);
			ti = add_item_to_tree(GTK_WIDGET(tree), pkt_offset+1, sv_length-1,
				"Non-Isolating Error Counts (%d total)",
				errors[0] + errors[1] + errors[2] + errors[3] + errors[4]);
			sv_tree = gtk_tree_new();
			add_subtree(ti, sv_tree, ETT_TR_NERR_CNT);

			add_item_to_tree(sv_tree, pkt_offset+2, 1,
				"Lost Frame Errors: %d", errors[0]);
			add_item_to_tree(sv_tree, pkt_offset+3, 1,
				"Receiver Congestion: %d", errors[1]);
			add_item_to_tree(sv_tree, pkt_offset+4, 1,
				"Frame-Copied Congestion: %d", errors[2]);
			add_item_to_tree(sv_tree, pkt_offset+5, 1,
				"Frequency Errors: %d", errors[3]);
			add_item_to_tree(sv_tree, pkt_offset+6, 1,
				"Token Errors: %d", errors[4]);
			break;

		case 0x30: /* Error Code */
			add_item_to_tree(tree, pkt_offset+1, sv_length-1,
				"Error Code: %04X", pntohs( &pd[2] ) );
			break;

		default: /* Unknown */
			add_item_to_tree(tree, pkt_offset+1, 1,
				"Unknown Sub-Vector: 0x%02X", pd[1]);
	}
	return sv_length;
}

void
dissect_trmac(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*mac_tree = NULL, *ti;
	int			mv_length, sv_length, sv_offset;
	char		*class[] = { "Ring Station", "LLC Manager", "", "",
		"Configuration Report Server", "Ring Parameter Server",
		"Ring Error Monitor" };
	char		*mv_text;

	mv_length = ntohs(*((guint16*)&pd[offset]));

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, mv_length,
			"Media Access Control");
		mac_tree = gtk_tree_new();
		add_subtree(ti, mac_tree, ETT_TR_MAC);
	}

	/* Interpret the major vector */
	mv_text = match_strval(pd[offset+3], major_vectors);

	/* Summary information */
	if (fd->win_info[COL_NUM]) {
		strcpy(fd->win_info[COL_PROTOCOL], "TR MAC");
		strcpy(fd->win_info[COL_INFO], mv_text);
	}

	if (tree) {
		if ((mv_text = match_strval(pd[offset+3], major_vectors)))
			add_item_to_tree(mac_tree, offset+3, 1, "Major Vector Command: %s",
							pd[offset+3]);
		else
			add_item_to_tree(mac_tree, offset+3, 1, "Major Vector Command: %02X (Unknown)",
							pd[offset+3]);
		add_item_to_tree(mac_tree, offset, 2, "Total Length: %d bytes",
			mv_length);
		add_item_to_tree(mac_tree, offset+2, 1, "Source Class: %s",
			class[ pd[offset+2] & 0x0f ]);
		add_item_to_tree(mac_tree, offset+2, 1, "Destination Class: %s",
			class[ pd[offset+2] >> 4 ]);

		/* interpret the subvectors */
		sv_offset = 0;
		offset += 4;
		sv_length = mv_length - 4;
		while (sv_offset < sv_length) {
			sv_offset += sv_text(&pd[offset + sv_offset], offset + sv_offset,
								mac_tree);
		}
	}
}
