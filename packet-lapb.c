/* packet-lapb.c
 * Routines for lapb frame disassembly
 * Olivier Abad <abad@daba.dhis.org>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
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

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include "packet.h"

#define LAPB_I          0x00    /* Information frames */
#define LAPB_S          0x01    /* Supervisory frames */
#define LAPB_U          0x03    /* Unnumbered frames */

#define LAPB_RR         0x01    /* Receiver ready */
#define LAPB_RNR        0x05    /* Receiver not ready */
#define LAPB_REJ        0x09    /* Reject */
#define LAPB_SABM       0x2F    /* Set Asynchronous Balanced Mode */
#define LAPB_SABME      0x6F    /* Set Asynchronous Balanced Mode Extended */
#define LAPB_DISC       0x43    /* Disconnect */
#define LAPB_DM         0x0F    /* Disconnected mode */
#define LAPB_UA         0x63    /* Unnumbered acknowledge */
#define LAPB_FRMR       0x87    /* Frame reject */

#define FROM_DCE	0x80

int proto_lapb = -1;
int hf_lapb_address = -1;
int hf_lapb_control = -1;

void
dissect_lapb(const u_char *pd, frame_data *fd, proto_tree *tree)
{
    proto_tree *lapb_tree, *ti;
    char lapb_addr[3];
    char info[80];

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "LAPB");

    sprintf(lapb_addr, "%2d", (int)pd[0]);
    if(check_col(fd, COL_RES_DL_SRC))
	col_add_str(fd, COL_RES_DL_SRC, lapb_addr);

    switch (pd[1] & 0x0F) {
    case LAPB_RR:
	if(check_col(fd, COL_INFO)) {
	    sprintf(info, "RR N(R):%d", (pd[1] >> 5) & 0x7);
	    if ((pd[1] >> 4) && 0x01) { /* P/F bit */
		if (((fd->flags & FROM_DCE) && pd[0] == 0x01) ||
		    (!(fd->flags & FROM_DCE) && pd[0] == 0x03))
		    strcat(info, " F");
		else
		    strcat(info, " P");
	    }
	    col_add_str(fd, COL_INFO, info);
	}
	if (fd->flags & FROM_DCE) {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DTE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DCE");
	}
	else {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DCE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DTE");
	}
	if (tree)
	{
	    ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
					    "LAPB");
	    lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1, pd[0],
				       "Address : 0x%02X", (int)pd[0]);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1, "RR",
				       "Control field : 0x%02X", (int)pd[1]);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     %d%d%d..... : N(R) = %d",
				(pd[1] >> 7) & 0x1,
				(pd[1] >> 6) & 0x1,
				(pd[1] >> 5) & 0x1,
				(pd[1] >> 5) & 0x7);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ...%d.... : Poll/Final bit",
				(pd[1] >> 4) & 0x1);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ....0001 : Receive Ready (RR)");
	}
	return;
    case LAPB_RNR:
	if(check_col(fd, COL_INFO)) {
	    sprintf(info, "RNR N(R):%d", (pd[1] >> 5) & 0x7);
	    if ((pd[1] >> 4) && 0x01) { /* P/F bit */
		if (((fd->flags & FROM_DCE) && pd[0] == 0x01) ||
		    (!(fd->flags & FROM_DCE) && pd[0] == 0x03))
		    strcat(info, " F");
		else
		    strcat(info, " P");
	    }
	    col_add_str(fd, COL_INFO, info);
	}
	if (fd->flags & FROM_DCE) {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DTE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DCE");
	}
	else {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DCE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DTE");
	}
	if (tree)
	{
	    ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
					    "LAPB");
	    lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1, pd[0],
				       "Address : 0x%02X", (int)pd[0]);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1, "RNR",
				       "Control field : 0x%02X", (int)pd[1]);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     %d%d%d..... : N(R) = %d",
				(pd[1] >> 7) & 0x1,
				(pd[1] >> 6) & 0x1,
				(pd[1] >> 5) & 0x1,
				(pd[1] >> 5) & 0x7);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ...%d.... : Poll/Final bit",
				(pd[1] >> 4) & 0x1);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ....0101 : Receive Not Ready (RNR)");
	}
	return;
    case LAPB_REJ:
	if(check_col(fd, COL_INFO)) {
	    sprintf(info, "REJ N(R):%d", (pd[1] >> 5) & 0x7);
	    if ((pd[1] >> 4) && 0x01) { /* P/F bit */
		if (((fd->flags & FROM_DCE) && pd[0] == 0x01) ||
		    (!(fd->flags & FROM_DCE) && pd[0] == 0x03))
		    strcat(info, " F");
		else
		    strcat(info, " P");
	    }
	    col_add_str(fd, COL_INFO, info);
	}
	if (fd->flags & FROM_DCE) {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DTE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DCE");
	}
	else {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DCE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DTE");
	}
	if (tree)
	{
	    ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
					    "LAPB");
	    lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1, pd[0],
				       "Address : 0x%02X", (int)pd[0]);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1, "REJ",
				       "Control field : 0x%02X", (int)pd[1]);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     %d%d%d..... : N(R) = %d",
				(pd[1] >> 7) & 0x1,
				(pd[1] >> 6) & 0x1,
				(pd[1] >> 5) & 0x1,
				(pd[1] >> 5) & 0x7);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ...%d.... : Poll/Final bit",
				(pd[1] >> 4) & 0x1);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ....1001 : Reeject (REJ)");
	}
	return;
    }

    /* not a RR/RNR/REJ frame */

    if (pd[1] & 0x01) { /* not an information frame */
	switch (pd[1] & 0xEF) { /* don't check Poll/Final bit */
	case LAPB_SABM:
	    if (fd->flags & FROM_DCE) {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DTE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DCE");
	    }
	    else {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DCE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DTE");
	    }
	    if(check_col(fd, COL_INFO)) {
		if (pd[1] & 0x10)
		    col_add_str(fd, COL_INFO, "SABM P");
		else
		    col_add_str(fd, COL_INFO, "SABM");
	    }
	    if (tree) {
		ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
						"LAPB");
		lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
		proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
					   pd[0], "Address: 0x%02X",
					   (int)pd[0]);
		proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
					   "SABM",
					   "Set Asynchronous Balanced Mode (SABM)");
		proto_tree_add_text(lapb_tree, 1, 1,
				    "...%d.... : Poll bit",
				    (pd[1] >> 4) & 0x1);
	    }
	    break;
	case LAPB_DISC:
	    if (fd->flags & FROM_DCE) {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DTE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DCE");
	    }
	    else {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DCE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DTE");
	    }
	    if(check_col(fd, COL_INFO)) {
		if (pd[1] & 0x10)
		    col_add_str(fd, COL_INFO, "DISC P");
		else
		    col_add_str(fd, COL_INFO, "DISC");
	    }
	    if (tree) {
		ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
						"LAPB");
		lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
		proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
					   pd[0], "Address: 0x%02X",
					   (int)pd[0]);
		proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
					   "DISC", "Disconnect (DISC)");
		proto_tree_add_text(lapb_tree, 1, 1,
				    "...%d.... : Poll bit",
				    (pd[1] >> 4) & 0x1);
	    }
	    break;
	case LAPB_DM:
	    if (fd->flags & FROM_DCE) {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DTE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DCE");
	    }
	    else {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DCE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DTE");
	    }
	    if(check_col(fd, COL_INFO)) {
		if (pd[1] & 0x10)
		    col_add_str(fd, COL_INFO, "DM F");
		else
		    col_add_str(fd, COL_INFO, "DM");
	    }
	    if (tree) {
		ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
						"LAPB");
		lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
		proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
					   pd[0], "Address: 0x%02X",
					   (int)pd[0]);
		proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
					   "DM", "Disconnect Mode (DM)");
		proto_tree_add_text(lapb_tree, 1, 1,
				    "...%d.... : Final bit",
				    (pd[1] >> 4) & 0x1);
	    }
	    break;
	case LAPB_UA:
	    if (fd->flags & FROM_DCE) {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DTE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DCE");
	    }
	    else {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DCE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DTE");
	    }
	    if(check_col(fd, COL_INFO)) {
		if (pd[1] & 0x10)
		    col_add_str(fd, COL_INFO, "UA F");
		else
		    col_add_str(fd, COL_INFO, "UA");
	    }
	    if (tree) {
		ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
						"LAPB");
		lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
		proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
					   pd[0], "Address: 0x%02X",
					   (int)pd[0]);
		proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
					   "UA", "Unnumbered Acknowledge (UA)");
		proto_tree_add_text(lapb_tree, 1, 1,
				    "...%d.... : Final bit",
				    (pd[1] >> 4) & 0x1);
	    }
	    break;
	case LAPB_FRMR:
	    if (fd->flags & FROM_DCE) {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DTE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DCE");
	    }
	    else {
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "DCE");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "DTE");
	    }
	    if(check_col(fd, COL_INFO)) {
		if (pd[1] & 0x10)
		    col_add_str(fd, COL_INFO, "FRMR F");
		else
		    col_add_str(fd, COL_INFO, "FRMR");
	    }
	    if (tree) {
		ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
						"LAPB");
		lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
		proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
					   pd[0], "Address: 0x%02X",
					   (int)pd[0]);
		proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
					   "FRMR", "Frame Reject (FRMR)");
		proto_tree_add_text(lapb_tree, 1, 1,
				    "...%d.... : Final bit",
				    (pd[1] >> 4) & 0x1);
	    }
	    break;
	}
    }
    else /* information frame */
    {
	if (fd->flags & FROM_DCE) {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DTE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DCE");
	}
	else {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, "DCE");
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, "DTE");
	}
	if(check_col(fd, COL_INFO)) {
	    sprintf(info, "I N(R):%d N(S):%d",
		    (pd[1] >> 5) & 0x7,
		    (pd[1] >> 1) & 0x7);
	    if ((pd[1] >> 4) && 0x01) /* P/F bit */
		strcat(info, " P");
	    col_add_str(fd, COL_INFO, info);
	}
	if (tree) {
	    ti = proto_tree_add_item_format(tree, proto_lapb, 0, 2, NULL,
					    "LAPB");
	    lapb_tree = proto_item_add_subtree(ti, ETT_LAPB);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_address, 0, 1,
				       pd[0], "Address: 0x%02X",
				       (int)pd[0]);
	    proto_tree_add_item_format(lapb_tree, hf_lapb_control, 1, 1,
				       "I", "Control field : 0x%02X",
				       (int)pd[1]);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     %d%d%d..... : N(R) = %d",
				(pd[1] >> 7) & 0x1,
				(pd[1] >> 6) & 0x1,
				(pd[1] >> 5) & 0x1,
				(pd[1] >> 5) & 0x7);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ...%d.... : Poll/Final bit",
				(pd[1] >> 4) & 0x1);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     ....%d%d%d. : N(S) = %d",
				(pd[1] >> 3) & 0x1,
				(pd[1] >> 2) & 0x1,
				(pd[1] >> 1) & 0x1,
				(pd[1] >> 1) & 0x7);
	    proto_tree_add_text(lapb_tree, 1, 1,
				"     .......0 : Information Transfer (I)");
	}
    }

    /* not end of frame ==> X.25 */
    if (fd->cap_len > 2) dissect_x25(pd, 2, fd, tree);
}

void
proto_register_lapb(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapb_address,
	  { "Address Field", "lapb.address", FT_UINT8, NULL} },
	{ &hf_lapb_control,
	  { "Control Field", "lapb.control", FT_STRING, NULL} },
    };

    proto_lapb = proto_register_protocol ("LAPB", "lapb");
    proto_register_field_array (proto_lapb, hf, array_length(hf));
}
