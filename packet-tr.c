/* packet-tr.c
 * Routines for Token-Ring packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-tr.c,v 1.5 1998/09/27 22:12:39 gerald Exp $
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

#include "ethereal.h"
#include "packet.h"
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
	int			frame_type;
	guint8			trn_rif_bytes;
	guint8			actual_rif_bytes;

	/* The trn_hdr struct, as separate variables */
	guint8			trn_ac;		/* access control field */
	guint8			trn_fc;		/* field control field */
	guint8			trn_dhost[6];	/* destination host */
	guint8			trn_shost[6];	/* source host */
	guint16			trn_rcf;	/* routing control field */
	guint16			trn_rseg[8];	/* routing registers */

	/* non-source-routed version of source addr */
	guint8			trn_shost_nonsr[6];


	/* Token-Ring Strings */
	char *fc[] = { "MAC", "LLC", "Reserved" };
	char *fc_pcf[] = {
		"Normal buffer", "Express buffer", "Purge",
		"Claim Token", "Beacon", "Active Monitor Present",
		"Standby Monitor Present" };
	char *rc_arrow[] = { "-->", "<--" };
	char *rc_direction[] = { "From originating station",
		"To originating station" };

	/* get the data */
	memcpy(&trn_ac, &pd[0], sizeof(guint8));
	memcpy(&trn_fc, &pd[1], sizeof(guint8));
	memcpy(trn_dhost, &pd[2], 6 * sizeof(guint8));
	memcpy(trn_shost, &pd[8], 6 * sizeof(guint8));
	memcpy(&trn_rcf, &pd[14], sizeof(guint16));
	memcpy(trn_rseg, &pd[16], 8 * sizeof(guint16));

	memcpy(trn_shost_nonsr, &pd[8], 6 * sizeof(guint8));
	trn_shost_nonsr[0] &= 127;
	frame_type = (trn_fc & 192) >> 6;

	/* if the high bit on the first byte of src hwaddr is 1, then
		this packet is source-routed */
	source_routed = trn_shost[0] & 128;

	trn_rif_bytes = pd[14] & 31;

	/* sometimes we have a RCF but no RIF... half source-routed? */
	/* I'll check for 2 bytes of RIF and the 0x70 byte */
	if (!source_routed) {
		if (trn_rif_bytes == 2) {
			source_routed = 1;
		}
		/* the Linux 2.0 TR code strips source-route bits in
		 * order to test for SR. This can be removed from most
		 * packets with oltr, but not all. So, I try to figure out
		 * which packets should have been SR here. I'll check to
		 * see if there's a SNAP or IPX field right after
		 * my RIF fields.
		 */
		else if ( (
			pd[0x0e + trn_rif_bytes] == 0xaa &&
			pd[0x0f + trn_rif_bytes] == 0xaa &&
			pd[0x10 + trn_rif_bytes] == 0x03) ||
			  (
			pd[0x0e + trn_rif_bytes] == 0xe0 &&
			pd[0x0f + trn_rif_bytes] == 0xe0) ) {

			source_routed = 1;
		}
/*		else {
			printf("0e+%d = %02X   0f+%d = %02X\n", trn_rif_bytes, pd[0x0e + trn_rif_bytes],
					trn_rif_bytes, pd[0x0f + trn_rif_bytes]);
		} */

	}

	if (source_routed) {
		actual_rif_bytes = trn_rif_bytes;
	}
	else {
		trn_rif_bytes = 0;
		actual_rif_bytes = 0;
	}

	/* this is a silly hack for Linux 2.0.x. Read the comment below,
	in front of the other #ifdef linux. If we're sniffing our own NIC,
	 we get a full RIF, sometimes with garbage */
	if ((source_routed && trn_rif_bytes == 2 && frame_type == 1) ||
		(!source_routed && frame_type == 1)) {
		/* look for SNAP or IPX only */
		if ( (pd[0x20] == 0xaa && pd[0x21] == 0xaa && pd[0x22] == 03) ||
			 (pd[0x20] == 0xe0 && pd[0x21] == 0xe0) ) {
			actual_rif_bytes = 18;
		}
	}
	offset += actual_rif_bytes;


	/* information window */
	if (fd->win_info[COL_NUM]) {
		strcpy(fd->win_info[COL_DESTINATION], ether_to_str((guint8 *)&pd[2]));
		strcpy(fd->win_info[COL_SOURCE], ether_to_str(trn_shost_nonsr));
		strcpy(fd->win_info[COL_PROTOCOL], "TR");
		sprintf(fd->win_info[COL_INFO], "Token-Ring %s", fc[frame_type]);
	}

	/* protocol analysis tree */
	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), 0, 14 + actual_rif_bytes,
		  "Token-Ring");
		fh_tree = gtk_tree_new();
		add_subtree(ti, fh_tree, ETT_TOKEN_RING);
		add_item_to_tree(fh_tree, 0, 1,
			"Access Control: %s, Priority=%d, Monitor Count=%d, "
			"Priority Reservation=%d",
			((trn_ac & 16) >> 4) ? "Frame" : "Token",	/* frame/token */
			((trn_ac & 224) >> 5),				/* priority */
			((trn_ac & 8) >> 3),				/* monitor count */
			((trn_ac & 7)));				/* priority reserv. */

		add_item_to_tree(fh_tree, 1, 1,
			"Frame Control: %s, Physical Control=%d (%s)",
			fc[frame_type], (trn_fc & 15),
			fc_pcf[(trn_fc & 15)]);

		add_item_to_tree(fh_tree, 2, 6, "Destination: %s",
			ether_to_str((guint8 *) trn_dhost));
		add_item_to_tree(fh_tree, 8, 6, "Source: %s",
			ether_to_str((guint8 *) trn_shost));

		if (source_routed) {
			add_item_to_tree(fh_tree, 14, 1, "RIF length: %d bytes", trn_rif_bytes);

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
			if (trn_rif_bytes > 2) {
				add_ring_bridge_pairs(trn_rif_bytes, pd, fh_tree);
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
		if (actual_rif_bytes > trn_rif_bytes) {
			printf("trn_rif %d    actual_rif %d\n", trn_rif_bytes, actual_rif_bytes);
			add_item_to_tree(fh_tree, 14 + trn_rif_bytes, actual_rif_bytes - trn_rif_bytes,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		/*
		if (source_routed && (trn_rif_bytes == 2) && silly_linux) {
			add_item_to_tree(fh_tree, 14 + trn_rif_bytes, 18 - actual_rif_bytes,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}
		else if ((!source_routed) && silly_linux ) {
			add_item_to_tree(fh_tree, 14, 18,
				"Empty RIF from Linux 2.0.x driver. The sniffing NIC "
				"is also running a protocol stack.");
		}*/
	}

	/* The package is either MAC or LLC */
	switch (frame_type) {
		/* MAC */
		case 0:
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

