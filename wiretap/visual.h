/* visual.h
 *
 * File read write routines for Visual Networks .cap files.
 * Copyright 2001, Tom Nisbet  tnisbet@visualnetworks.com
 *
 * Based on the code that handles netmon files.
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

#ifndef __VISUAL_H__
#define __VISUAL_H__

int visual_open(wtap *wth, int *err, gchar **err_info);
gboolean visual_dump_open(wtap_dumper *wdh, int *err);
int visual_dump_can_write_encap(int encap);

#endif
