/* globals.h
 * Global defines, etc.
 *
 * $Id: globals.h,v 1.25 2001/05/01 00:18:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <stdio.h>
#include "file.h"
#include "timestamp.h"

#define MIN_PACKET_SIZE 68	/* minimum amount of packet data we can read */

extern capture_file cfile;
extern guint        main_ctx, file_ctx;
extern gchar       *ethereal_path;
extern gchar       *last_open_dir;
extern field_info  *finfo_selected;

extern ts_type timestamp_type;

#endif
