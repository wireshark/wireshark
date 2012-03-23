/* packet-mpeg-sect.h
 * Declarations of exported routines from mpeg-sect dissector
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
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

#ifndef __PACKET_MPEG_SECT_H_
#define __PACKET_MPEG_SECT_H__

#define PACKET_MPEG_SECT_PI__TABLE_ID	0
#define PACKET_MPEG_SECT_PI__SSI	1
#define PACKET_MPEG_SECT_PI__RESERVED	2
#define PACKET_MPEG_SECT_PI__LENGTH	3
#define PACKET_MPEG_SECT_PI__SIZE	4

/* convert a byte that contains two 4bit BCD digits into a decimal value */
#define MPEG_SECT_BCD44_TO_DEC(x)  (((x&0xf0) >> 4) * 10 + (x&0x0f))

/*
 * Used to read a date provided in MJD format into a utc_time structure
 */
extern gint
packet_mpeg_sect_mjd_to_utc_time(tvbuff_t *tvb, gint offset, nstime_t *utc_time);

/*
 *  Used to process the 'standard' mpeg section header that is described below
 *  and populate the data into the tree
 */
extern guint
packet_mpeg_sect_header(tvbuff_t *tvb, guint offset,
			proto_tree *tree, guint *sect_len, gboolean *ssi);

/*
 *  Used to return all the values & items for 'strict' processing of the
 *  sub-dissectors that make use of this dissector
 */
extern guint
packet_mpeg_sect_header_extra(tvbuff_t *tvb, guint offset, proto_tree *tree,
				guint *sect_len, guint *reserved, gboolean *ssi,
				proto_item **items);

/*
 *  Used to process the mpeg CRC information & report erorrs found with it.
 */
extern void
packet_mpeg_sect_crc(tvbuff_t *tvb, packet_info *pinfo,
						proto_tree *tree, guint start, guint end);
#endif
