/* globals.h
 * Global defines, etc.
 *
 * $Id: globals.h,v 1.21 2000/08/20 07:53:30 guy Exp $
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
#include "packet.h"
#include "file.h"
#include "timestamp.h"

#define MIN_PACKET_SIZE 68	/* minimum amount of packet data we can read */

/* Byte swapping routines */
#define SWAP16(x) \
  ( (((x) & 0x00ff) << 8) | \
    (((x) & 0xff00) >> 8) )
#define SWAP32(x) \
  ( (((x) & 0x000000ff) << 24) | \
    (((x) & 0x0000ff00) <<  8) | \
    (((x) & 0x00ff0000) >>  8) | \
    (((x) & 0xff000000) >> 24) )

/* Byte ordering */
#ifndef BYTE_ORDER
# define LITTLE_ENDIAN 4321
# define BIG_ENDIAN 1234
# ifdef WORDS_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# else
#  define BYTE_ORDER LITTLE_ENDIAN
# endif
#endif

/* From the K&R book, p. 89 */
#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

extern packet_info  pi;
extern capture_file cfile;
extern guint        main_ctx, file_ctx;
extern gchar        comp_info_str[256];
extern gchar       *ethereal_path;
extern gchar       *last_open_dir;
extern gboolean     auto_scroll_live;
extern int          g_resolving_actif;
extern gboolean     g_ip_dscp_actif;
extern field_info  *finfo_selected;

extern ts_type timestamp_type;

#define PF_DIR ".ethereal"

#endif
