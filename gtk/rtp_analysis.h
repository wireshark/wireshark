/* rtp_analysis.h
 * RTP analysis addition for ethereal
 *
 * $Id: rtp_analysis.h,v 1.1 2003/09/24 07:48:11 guy Exp $
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * based on tap_rtp.c
 * Copyright 2003, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef RTP_ANALYSIS_H_INCLUDED
#define RTP_ANALYSIS_H_INCLUDED

#include <glib.h>

void rtp_analysis(
		guint32 ip_src_fwd,  /* network-order IPv4 address */
		guint16 port_src_fwd,
		guint32 ip_dst_fwd,  /* network-order IPv4 address */
		guint16 port_dst_fwd,
		guint32 ssrc_fwd,
		guint32 ip_src_rev,  /* network-order IPv4 address */
		guint16 port_src_rev,
		guint32 ip_dst_rev,  /* network-order IPv4 address */
		guint16 port_dst_rev,
		guint32 ssrc_rev
		);

#endif /*RTP_ANALYSIS_H_INCLUDED*/
