/* packet-ppp.h
 *
 * $Id: packet-ppp.h,v 1.12 2002/11/11 19:23:12 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PACKET_PPP_H__
#define __PACKET_PPP_H__

/* PPP options */
extern gboolean ppp_vj_decomp;/* FALSE = No VJ header decompression,
                                 TRUE  = Decompress VJ */
void capture_ppp_hdlc(const guchar *, int, int, packet_counts *);

/*
 * Used by the GTP dissector as well.
 */
extern dissector_table_t ppp_subdissector_table;
extern const value_string ppp_vals[];

#endif
