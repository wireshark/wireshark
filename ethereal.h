/* ethereal.h
 * Global defines, etc.
 *
 * $Id: ethereal.h,v 1.7 1998/10/16 01:18:27 gerald Exp $
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

#ifndef __ETHEREAL_H__
#define __ETHEREAL_H__

#include "config.h"

#define RC_FILE ".etherealrc"
#define MONO_MEDIUM_FONT "-*-lucidatypewriter-medium-r-normal-*-*-120-*-*-*-*-iso8859-1"
#define MONO_BOLD_FONT "-*-lucidatypewriter-bold-r-normal-*-*-120-*-*-*-*-iso8859-1"
#define DEF_WIDTH 750
#define DEF_HEIGHT 550
#define DEF_READY_MESSAGE " Ready to load or capture"
#define EXTERNAL_FILTER "/usr/local/bin/ethereal_tcp_filter -f" 

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
  #define LITTLE_ENDIAN 4321
  #define BIG_ENDIAN 1234
  #ifdef WORDS_BIGENDIAN
    #define BYTE_ORDER BIG_ENDIAN
  #else
    #define BYTE_ORDER LITTLE_ENDIAN
  #endif
#endif

/* From the K&R book, p. 89 */
#ifndef MAX
  #define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
  #define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
    
typedef struct _selection_info {
  GtkWidget *tree;
  GtkWidget *text;
} selection_info;

/*
 * Columns in summary listing.
 */
#define	COL_NUM		0
#define	COL_TIME	1
#define	COL_SOURCE	2
#define	COL_DESTINATION	3
#define	COL_PROTOCOL	4
#define	COL_INFO	5

#define	NUM_COLS	6

/*
 * Type of time-stamp shown in the summary display.
 */
typedef enum {
	RELATIVE,
	ABSOLUTE,
	DELTA
} ts_type;

extern ts_type timestamp_type;

void about_ethereal( GtkWidget *, gpointer);
void file_sel_ok_cb(GtkWidget *, GtkFileSelection *);
void blank_packetinfo();
gint file_progress_cb(gpointer);
void follow_stream_cb( GtkWidget *, gpointer);
void file_open_cmd_cb(GtkWidget *, gpointer);
void file_close_cmd_cb(GtkWidget *, gpointer);
void file_quit_cmd_cb(GtkWidget *, gpointer);
void file_reload_cmd_cb(GtkWidget *, gpointer);
void file_print_cmd_cb(GtkWidget *, gpointer);
void main_realize_cb(GtkWidget *, gpointer);

#endif /* ethereal.h */
