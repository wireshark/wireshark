/* ethereal.h
 * Global defines, etc.
 *
 * $Id: ethereal.h,v 1.9 1998/12/17 05:42:22 gram Exp $
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

#define PF_DIR ".ethereal"
#define RC_FILE PF_DIR "/gtkrc"
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

/* Determine whether we use menu factories or item factories. This
 * code snippet is taken from cheops.h of cheops-0.57, a GPL'ed
 * network utility program Copyright (C) 1998, Mark Spencer
 */
#if (GTK_MINOR_VERSION > 1) || ((GTK_MICRO_VERSION > 1) &&  (GTK_MINOR_VERSION > 0))
	#define USE_ITEM
	#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))
#else
	#undef USE_ITEM
	typedef void (*_GTK_MENU_FUNC_T)(GtkWidget *, void *);
	#define GTK_MENU_FUNC(a) ((_GTK_MENU_FUNC_T)(a))
#endif

    
typedef struct _selection_info {
  GtkWidget *tree;
  GtkWidget *text;
} selection_info;

/*
 * All of the possible columns in summary listing.
 *
 * NOTE: The SRC and DST entries MUST remain in this order, or else you
 * need to fix the offset #defines before get_column_format!
 */
enum {
  COL_NUMBER,         /* Packet list item number */
  COL_REL_TIME,       /* Relative time (default) */
  COL_ABS_TIME,       /* Absolute time */
  COL_DELTA_TIME,     /* Delta time */
  COL_DEF_SRC,        /* Source address */
  COL_RES_SRC,        /* Resolved source */
  COL_UNRES_SRC,      /* Unresolved source */
  COL_DEF_DL_SRC,     /* Data link layer source address */
  COL_RES_DL_SRC,     /* Resolved DL source */
  COL_UNRES_DL_SRC,   /* Unresolved DL source */
  COL_DEF_NET_SRC,    /* Network layer source address */
  COL_RES_NET_SRC,    /* Resolved net source */
  COL_UNRES_NET_SRC,  /* Unresolved net source */
  COL_DEF_DST,        /* Destination address */
  COL_RES_DST,        /* Resolved dest */
  COL_UNRES_DST,      /* Unresolved dest */
  COL_DEF_DL_DST,     /* Data link layer dest address */
  COL_RES_DL_DST,     /* Resolved DL dest */
  COL_UNRES_DL_DST,   /* Unresolved DL dest */
  COL_DEF_NET_DST,    /* Network layer dest address */
  COL_RES_NET_DST,    /* Resolved net dest */
  COL_UNRES_NET_DST,  /* Unresolved net dest */
  COL_DEF_SRC_PORT,   /* Source port */
  COL_RES_SRC_PORT,   /* Resolved source port */
  COL_UNRES_SRC_PORT, /* Unresolved source port */
  COL_DEF_DST_PORT,   /* Destination port */
  COL_RES_DST_PORT,   /* Resolved dest port */
  COL_UNRES_DST_PORT, /* Unresolved dest port */
  COL_PROTOCOL,       /* Protocol */
  COL_INFO,           /* Description */
  NUM_COL_FMTS        /* Should always be last */
};

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
