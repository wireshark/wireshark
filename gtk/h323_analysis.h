/* h323_analysis.h
 * H323 analysis addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
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

#ifndef H323_ANALYSIS_H_INCLUDED
#define H323_ANALYSIS_H_INCLUDED

#include <glib.h>

/** @file
 *  ??? 
 *  @todo what's this?
 */

void h323_analysis(
		guint32 ip_src,  /* network-order IPv4 address */
		guint16 port_src,
		guint32 ip_dst,  /* network-order IPv4 address */
		guint16 port_dst,
		guint32 ip_src_h245,  /* network-order IPv4 address */
		guint16 port_src_h245,
		guint16 transport
		);

#endif /* H323_ANALYSIS_H_INCLUDED*/
