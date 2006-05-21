/* packet-nhrp.h
 * Definitions for NHRP
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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


#ifndef __PACKET_NHRP_H__
#define __PACKET_NHRP_H__

typedef struct _e_nhrp {
	guint16	ar_afn;
	guint16	ar_pro_type;
	guint8	ar_pro_snap[5];
	guint8	ar_hopCnt;
	guint16	ar_pktsz;
	guint16	ar_chksum;
	guint16	ar_extoff;
	guint8	ar_op_version;
	guint8	ar_op_type;
	guint8	ar_shtl;
	guint8	ar_sstl;
} e_nhrp_hdr;

void capture_nhrp(const guchar *, int, int, packet_counts *);

/* Export the DSCP value-string table for other protocols */
/*extern const value_string dscp_vals[];*/

#endif
