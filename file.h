/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.85 2001/12/04 07:32:00 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __FILE_H__
#define __FILE_H__

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "wiretap/wtap.h"
#include "dfilter/dfilter.h"
#include "print.h"
#include <errno.h>
#include <epan.h>

/* Current state of file. */
typedef enum {
	FILE_CLOSED,		/* No file open */
	FILE_READ_IN_PROGRESS,	/* Reading a file we've opened */
	FILE_READ_ABORTED,	/* Read aborted by user */
	FILE_READ_DONE		/* Read completed */
} file_state;

typedef struct _capture_file {
  file_state   state;     /* Current state of capture file */
  int          filed;     /* File descriptor of capture file */
  gchar       *filename;  /* Name of capture file */
  gboolean     is_tempfile; /* Is capture file a temporary file? */
  gboolean     user_saved;/* If capture file is temporary, has it been saved by user yet? */
  long         f_len;     /* Length of capture file */
  guint16      cd_t;      /* File type of capture file */
  int          lnk_t;     /* Link-layer type with which to save capture */
  guint32      vers;      /* Version.  For tcpdump minor is appended to major */
  int          count;     /* Packet count */
  gboolean     drops_known; /* TRUE if we know how many packets were dropped */
  guint32      drops;     /* Dropped packets */
  guint32      esec;      /* Elapsed seconds */
  guint32      eusec;     /* Elapsed microseconds */
  int          snap;      /* Captured packet length */
  long         progbar_quantum; /* Number of bytes read per progress bar update */
  long         progbar_nextstep; /* Next point at which to update progress bar */
  gchar       *iface;     /* Interface */
  gchar       *save_file; /* File that user saved capture to */
  int          save_file_fd; /* File descriptor for saved file */
  wtap        *wth;       /* Wiretap session */
  dfilter_t   *rfcode;    /* Compiled read filter program */ 
  gchar       *dfilter;   /* Display filter string */
  struct _colfilter   *colors;	  /* Colors for colorizing packet window */
  dfilter_t   *dfcode;    /* Compiled display filter program */ 
#ifdef HAVE_LIBPCAP
  gchar       *cfilter;   /* Capture filter string */
#endif
  gchar       *sfilter;   /* Search filter string */
  gboolean     sbackward;  /* TRUE if search is backward, FALSE if forward */
  union wtap_pseudo_header pseudo_header;      /* Packet pseudo_header */
  guint8       pd[WTAP_MAX_PACKET_SIZE];  /* Packet data */
  GMemChunk   *plist_chunk; /* Memory chunk for frame_data structures */
  frame_data  *plist;     /* Packet list */
  frame_data  *plist_end; /* Last packet in list */
  frame_data  *first_displayed; /* First frame displayed */
  frame_data  *last_displayed;  /* Last frame displayed */
  column_info  cinfo;    /* Column formatting information */
  frame_data  *current_frame;  /* Frame data for current frame */
  proto_tree  *protocol_tree; /* Protocol tree for currently selected packet */
  epan_dissect_t *edt; /* Protocol dissection fo rcurrently selected packet */
  FILE        *print_fh;  /* File we're printing to */
#ifdef HAVE_LIBPCAP
  guint32      autostop_filesize; /* Maximum capture file size */
  gint32       autostop_duration; /* Maximum capture duration */
#endif
} capture_file;

/* Return values from "read_cap_file()", "continue_tail_cap_file()",
   and "finish_tail_cap_file()". */
typedef enum {
	READ_SUCCESS,	/* read succeeded */
	READ_ERROR,	/* read got an error */
	READ_ABORTED	/* read aborted by user */
} read_status_t;

int  open_cap_file(char *, gboolean, capture_file *);
void close_cap_file(capture_file *);
read_status_t read_cap_file(capture_file *, int *);
int  start_tail_cap_file(char *, gboolean, capture_file *);
read_status_t continue_tail_cap_file(capture_file *, int, int *);
read_status_t finish_tail_cap_file(capture_file *, int *);
/* size_t read_frame_header(capture_file *); */
int  save_cap_file(char *, capture_file *, gboolean, gboolean, guint);

int filter_packets(capture_file *cf, gchar *dfilter);
void colorize_packets(capture_file *);
void redissect_packets(capture_file *cf);
int print_packets(capture_file *cf, print_args_t *print_args);
void change_time_formats(capture_file *);
gboolean find_packet(capture_file *cf, dfilter_t *sfcode);

typedef enum {
  FOUND_FRAME,		/* found the frame */
  NO_SUCH_FRAME,	/* no frame with that number */
  FRAME_NOT_DISPLAYED	/* frame with that number isn't displayed */
} goto_result_t;
goto_result_t goto_frame(capture_file *cf, guint fnumber);

void select_packet(capture_file *, int);
void unselect_packet(capture_file *);

void unselect_field(void);

/* Moves or copies a file. Returns 0 on failure, 1 on success */
int file_mv(char *from, char *to);

/* Copies a file. Returns 0 on failure, 1 on success */
int file_cp(char *from, char *to);

char *file_open_error_message(int, gboolean);
char *file_read_error_message(int);
char *file_write_error_message(int);

#endif /* file.h */
