/* globals.h
 * Global defines, etc.
 *
 * $Id: globals.h,v 1.9 1999/09/30 06:49:54 guy Exp $
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

#ifndef _STDIO_H_
#include <stdio.h>
#endif

#ifndef __PACKET_H__
#include "packet.h"
#endif

#ifndef __GTK_H__
#include <gtk/gtk.h>
#endif

#ifndef __PRINT_H__
#include "print.h"
#endif

#ifndef __FILE_H__
#include "file.h"
#endif

#ifndef __TIMESTAMP_H__
#include "timestamp.h"
#endif

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

extern FILE        *data_out_file;
extern packet_info  pi;
extern capture_file cf;
extern GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
            *info_bar;
extern GdkFont     *m_r_font, *m_b_font;
extern guint        main_ctx, file_ctx;
extern gchar        comp_info_str[256];
extern gchar       *ethereal_path;
extern gchar       *medium_font;
extern gchar       *bold_font;
extern gchar       *last_open_dir;
extern gboolean     auto_scroll_live;
extern int          g_resolving_actif;

extern ts_type timestamp_type;

extern GtkStyle *item_style;

#ifdef HAVE_LIBPCAP
extern int sync_mode;	/* allow sync */
extern int sync_pipe[2]; /* used to sync father */
extern int fork_mode;	/* fork a child to do the capture */
extern int quit_after_cap; /* Makes a "capture only mode". Implies -k */
extern gboolean capture_child;	/* if this is the child for "-F"/"-S" */
#endif

#define PF_DIR ".ethereal"

#endif
