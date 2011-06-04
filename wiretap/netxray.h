/* netxray.h
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef __NETXRAY_H__
#define __NETXRAY_H__

#include <glib.h>
#include <wtap.h>

int netxray_open(wtap *wth, int *err, gchar **err_info);
int netxray_dump_can_write_encap_1_1(int encap);
gboolean netxray_dump_open_1_1(wtap_dumper *wdh, int *err);
int netxray_dump_can_write_encap_2_0(int encap);
gboolean netxray_dump_open_2_0(wtap_dumper *wdh, int *err);

#endif
