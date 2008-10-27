/* geoip.h
 * GeoIP database support
 *
 * $Id$
 *
 * Copyright 2008, Gerald Combs <gerald@wireshark.org>
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

#ifndef __GEOIP_H__
#define __GEOIP_H__

/**
 * Init function called from epan.h
 */
extern void geoip_init(void);

/**
 * Number of databases we have loaded
 *
 * @return The number GeoIP databases successfully loaded
 */
extern guint geoip_num_dbs(void);

/**
 * Fetch the name of a database
 *
 * @param dbnum Database index
 * @return The number GeoIP databases successfully loaded
 */
const gchar *geoip_db_name(guint dbnum);

/**
 * Look up an IPv4 address in a database
 *
 * @param dbnum Database index
 * @param addr IPv4 address to look up
 * @return The number GeoIP databases successfully loaded
 */
const char *geoip_db_lookup_ipv4(guint dbnum, guint32 addr);

/**
 * Get all configured paths
 *
 * @return String with all paths separated by a path separator
 */
extern gchar *geoip_get_paths(void);

#endif /* __GEOIP_H__ */
