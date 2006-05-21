/* cfile.h
 * capture_file definition & GUI-independent manipulation
 *
 * $Id$
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

#ifndef __CFILE_H__
#define __CFILE_H__

/* Current state of file. */
typedef enum {
	FILE_CLOSED,		/* No file open */
	FILE_READ_IN_PROGRESS,	/* Reading a file we've opened */
	FILE_READ_ABORTED,	/* Read aborted by user */
	FILE_READ_DONE		/* Read completed */
} file_state;

/* Character set for text search. */
typedef enum {
	SCS_ASCII_AND_UNICODE,
	SCS_ASCII,
	SCS_UNICODE
	/* add EBCDIC when it's implemented */
} search_charset_t;

typedef struct _capture_file {
  file_state   state;     /* Current state of capture file */
  gchar       *filename;  /* Name of capture file */
  gboolean     is_tempfile; /* Is capture file a temporary file? */
  gboolean     user_saved;/* If capture file is temporary, has it been saved by user yet? */
  long         f_datalen; /* Size of capture file data (uncompressed) */
  guint16      cd_t;      /* File type of capture file */
  int          lnk_t;     /* Link-layer type with which to save capture */
  guint32      vers;      /* Version.  For tcpdump minor is appended to major */
  int          count;     /* Total number of frames */
  int          displayed_count; /* Number of displayed frames */
  int          marked_count; /* Number of marked frames */
  gboolean     drops_known; /* TRUE if we know how many packets were dropped */
  guint32      drops;       /* Dropped packets */
  nstime_t     elapsed_time;/* Elapsed time */
  gboolean     has_snap;  /* TRUE if maximum capture packet length is known */
  int          snap;      /* Maximum captured packet length */
  wtap        *wth;       /* Wiretap session */
  dfilter_t   *rfcode;    /* Compiled read (display) filter program */
  gchar       *dfilter;   /* Display filter string */
  dfilter_t   *dfcode;    /* Compiled display filter program */
  /* search */
  gchar       *sfilter;   /* Search filter string */
  gboolean     sbackward; /* TRUE if search is backward, FALSE if forward */
  gboolean     hex;       /* TRUE is raw data search is being performed */
  gboolean     string;    /* TRUE is text search is being performed */
  search_charset_t scs_type; /* Character set for text search */
  gboolean     case_type; /* TRUE if case-insensitive text search */
  gboolean     decode_data; /* TRUE if searching protocol tree text */
  gboolean     summary_data; /* TRUE if searching Info column text */
  /* packet data */
  union wtap_pseudo_header pseudo_header;      /* Packet pseudo_header */
  guint8       pd[WTAP_MAX_PACKET_SIZE];  /* Packet data */
  GMemChunk   *plist_chunk; /* Memory chunk for frame_data structures */
  frame_data  *plist;     /* Packet list */
  frame_data  *plist_end; /* Last packet in list */
  frame_data  *first_displayed; /* First frame displayed */
  frame_data  *last_displayed;  /* Last frame displayed */
  column_info  cinfo;    /* Column formatting information */
  frame_data  *current_frame;  /* Frame data for current frame */
  epan_dissect_t *edt; /* Protocol dissection for currently selected packet */
  field_info  *finfo_selected;	/* Field info for currently selected field */
  struct ph_stats_s* pstats; /* accumulated stats (reset on redisplay in GUI)*/
} capture_file;

void init_cap_file(capture_file *);

#endif /* cfile.h */
