/* packet-tr.c
 * Routines for Token-Ring packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-tr.c,v 1.3 1998/09/17 03:29:27 gram Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <pcap.h>

#include "packet.h"
#include "ethereal.h"
#include "etypes.h"

static void
add_ring_bridge_pairs(int rcf_len, const u_char *pd, GtkWidget *tree);

static char*
sr_broadcast(u_char val) {

	if (val < 4) {
		return "Non-broadcast";
	}
	else if (val < 6) {
		return "All-routes broadcast";
	}
	else {
		return "Single-route broadcast";
	}
}

static int
sr_frame(u_char val) {

	int rc_frame[7] = { 516, 1500, 2052, 4472, 8144, 11407, 17800 };

	if (val > 6) {
		return -1;
	}
	else return rc_frame[val];
}

void
dissect_tr(const u_char *pd, frame_data *fd, GtkTree *tree) {

	GtkWidget	*fh_tree, *ti;
	int			offset = 14;
	int			source_routed = 0;
	int			rif_bytes = 0;
	int			true_rif_bytes = 0;	/* because of silly_linux */
	guint8		nonsr_hwaddr[8];
	int			frame_type = (pd[1] & 192) >> 6; /* I use this value a lot */
	#ifdef linux
	int			silly_linux = 0;
	#endif

	/* Token-Ring Strings */
	char *fc[] = { "MAC", "LLC", "Reserved" };
	char *fc_pcf[] = {
		"Normal buffer", "Express buffer", "Purge",
		"Claim Token", "Beacon", "Active Monitor Present",
		"Standby Monitor Present" };
	char *rc_arrow[] = { "-->", "<--" };
	char *rc_direction[] = { "From originating station",
		"To originating station" };

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = pd[8] & 128;

	/* sometimes we have a RCF but no RIF... half source-routed? */
	/* I'll check for 2 bytes of RIF and the 0x70 byte */
	if (!source_routed) {
		if ((pd[14] & 31) == 2) {
			source_routed = 1;
		}
	}

	if (source_routed) {
		rif_bytes = pd[14] & 31;
		true_rif_bytes = rif_bytes;
	}
	/* this is a silly hack for Linux 2.0.x. Read the comment below,
	in front of the other #ifdef linux */
	#ifdef linux
	if ((source_routed && rif_bytes == 2 && frame_type == 1) ||
		(!source_routed && frame_type == 1)) {
		/* look for SNAP or IPX only */
		if ( (pd[0x20] == 0xaa && pd[0x21] == 0xaa && pd[0x22] == 03) ||
			 (pd[0x20] == 0xe0 && pd[0x21] == 0xe0) ) {
			silly_linux = 1;
			rif_bytes = 18;
		}
	}
	#endif
	offset += rif_bytes;

	/* Make a copy of the src hwaddr, w/o source routing. I'll do this
		for all packets, even non-sr packets */
	memcpy(nonsr_hwaddr, &pd[8], 6);
	nonsr_hwaddr[0] &= 127;

	if (fd->win_info[0]) {
		strcpy(fd->win_info[2], ether_to_str((guint8 *)&pd[2]));
		strcpy(fd->win_info[1], ether_to_str(nonsr_hwaddr));
		strcpy(fd->win_info[3], "TR");
		sprintf(fd->win_info[4], "Token-Ring %s", fc[frame_type]);
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), 0, 14 + rif_bytes,
		  "Token-Ring (%d on wire, %d captured)", fd->pkt_len, fd->cap_len);
		fh_tree = gtk_tree_new();
		add_subtree(ti, fh_tree, ETT_TOKEN_RING);
		add_item_to_tree(fh_tree, 0, 1,
			"Access Control: %s, Priority=%d, Monitor Count=%d, "
			"Priority Reservation=%d",
			((pd[0] & 16) >> 4) ? "Frame" : "Token",	/* frame/token */
			((pd[0] & 224) >> 5),						/* priority */
			((pd[0] & 8) >> 3),							/* monitor count */
			((pd[0] & 7)));								/* priority reserv. */

		add_item_to_tree(fh_tree, 1, 1,
			"Frame Control: %s, Physical Control=%d (%s)",
			fc[frame_type], (pd[1] & 15),
			fc_pcf[(pd[1] & 15)]);

		add_item_to_tree(fh_tree, 2, 6, "Destination: %s",
			ether_to_str((guint8 *) &pd[2]));
		add_item_to_tree(fh_tree, 8, 6, "Source: %s",
			ether_to_str((guint8 *) &pd[8]));

		if (source_routed) {
			add_item_to_tree(fh_tree, 14, 1, "RIF length: %d bytes", true_rif_bytes);

			add_item_to_tree(fh_tree, 15, 1,
				"%s, up to %d bytes in frame (LF=%d)",
				sr_broadcast((pd[14] & 224) >> 5),
				sr_frame((pd[15] & 112) >> 4),
				(pd[15] & 112) >> 4);

			add_item_to_tree(fh_tree, 15, 1,
				"Direction: %s (%s)",
				rc_direction[(pd[15] & 128) >> 7],
				rc_arrow[(pd[15] & 128) >> 7]);

			/* if we have more than 2 bytes of RIF, then we have
				ring/bridge pairs */
			if (true_rif_bytes > 2) {
				add_ring_bridge_pairs(rif_bytes, pd, fh_tree);
			}
		}

		/* Linux 2.0.x has a problem in that the 802.5 code creates
		an emtpy full (18-byte) RIF area. It's up to the tr driver to
		either fill it in or remove it before sending the bytes out
		to the wire. If you run tcpdump on a Linux 2.0.x machine running
		token-ring, tcpdump will capture these 18 filler bytes. They
		are filled with garbage. The best way to detect this problem is
		to know the src hwaddr of the machine from which you were running
		tcpdump. W/o that, however, I'm guessing that DSAP == SSAP if the
		frame type is LLC.  It's very much a hack. -- Gilbert Ramirez */
		#ifdef linux
		if (source_routed && (true_rif_bytes == 2) && silly_linux) {
			add_item_to_tree(fh_tree, 14 + true_rif_bytes, 18 - true_rif_bytes,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		else if ((!source_routed) && silly_linux ) {
			add_item_to_tree(fh_tree, 14, 18,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		#endif
	}

	/* The package is either MAC or LLC */
	switch (frame_type) {
		/* MAC */
		case 0:
			/* dissect_trmac(pd, offset, fd, tree) */
			dissect_trmac(pd, offset, fd, tree);
			break;
		case 1:
			dissect_llc(pd, offset, fd, tree);
			break;
		default:
			/* non-MAC, non-LLC, i.e., "Reserved" */
			dissect_data(pd, offset, fd, tree);
			break;
	}
}

/* this routine is taken from the Linux net/802/tr.c code, which shows
ring-bridge paires in the /proc/net/tr_rif virtual file. */
static void
add_ring_bridge_pairs(int rcf_len, const u_char *pd, GtkWidget *tree)
{
	int 	j, size;
	int 	segment, brdgnmb;
	char	buffer[50];
	int		buff_offset=0;

	rcf_len -= 2;

	if (rcf_len)
		rcf_len >>= 1;

	for(j = 1; j < rcf_len; j++) {
		if (j==1) {
			segment=ntohs(*((unsigned short*)&pd[16])) >> 4;
			size = sprintf(buffer,"%03X",segment);
			buff_offset += size;
		}
		segment=ntohs(*((unsigned short*)&pd[17+j])) >> 4;
		brdgnmb=pd[16+j] & 0x0f;
		size = sprintf(buffer+buff_offset,"-%01X-%03X",brdgnmb,segment);
		buff_offset += size;	
	}

	add_item_to_tree(tree, 16, rcf_len << 1,
		"Ring-Bridge Pairs: %s",
		buffer);

}

