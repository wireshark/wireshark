/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.61 1999/12/10 04:20:53 gram Exp $
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

#ifndef __FILE_H__
#define __FILE_H__

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifndef __WTAP_H__
#include "wiretap/wtap.h"
#endif

#ifdef HAVE_LIBPCAP
#ifndef lib_pcap_h
#include <pcap.h>
#endif
#endif

#ifndef __DFILTER_H__
#include "dfilter.h"
#endif

#ifndef __COLORS_H__
#include "colors.h"
#endif

#ifndef __PRINT_H__
#include "print.h"
#endif

#include <errno.h>

#ifdef HAVE_LIBZ
#include "zlib.h"

#define FILE_T gzFile
#define file_open gzopen
#define filed_open gzdopen
#define file_seek gzseek
#define file_read(buf, bsize, count, file) gzread((file),(buf),((count)*(bsize)))
#define file_write(buf, bsize, count, file) gzwrite((file),(buf),((count)*(bsize)))
#define file_close gzclose

#else /* No zLib */
#define FILE_T FILE *
#define file_open fopen
#define filed_open fdopen
#define file_seek fseek
#define file_read fread
#define file_write fwrite
#define file_close fclose
#endif /* HAVE_LIBZ */

typedef struct bpf_program bpf_prog;

typedef struct _capture_file {
  FILE_T       fh;        /* File handle for capture file */
  int          filed;     /* File descriptor of capture file */
  gchar       *filename;  /* Name of capture file */
  gboolean     is_tempfile; /* Is capture file a temporary file? */
  gboolean     user_saved;/* If capture file is temporary, has it been saved by user yet? */
  long         f_len;     /* Length of capture file */
  guint16      cd_t;      /* File type of capture file */
  int          lnk_t;     /* Link-layer type with which to save capture */
  guint32      vers;      /* Version.  For tcpdump minor is appended to major */
  guint32      count;     /* Packet count */
  gfloat       unfiltered_count; /* used for dfilter progress bar */
  guint32      drops;     /* Dropped packets */
  guint32      esec;      /* Elapsed seconds */
  guint32      eusec;     /* Elapsed microseconds */
  guint32      snap;      /* Captured packet length */
  gboolean     update_progbar; /* TRUE if we should update the progress bar */
  long         progbar_quantum; /* Number of bytes read per progress bar update */
  long         progbar_nextstep; /* Next point at which to update progress bar */
  gchar       *iface;     /* Interface */
  gchar       *save_file; /* File that user saved capture to */
  int          save_file_fd; /* File descriptor for saved file */
  wtap        *wth;       /* Wiretap session */
  dfilter     *rfcode;    /* Compiled read filter program */ 
  gchar       *dfilter;   /* Display filter string */
  colfilter   *colors;	  /* Colors for colorizing packet window */
  dfilter     *dfcode;    /* Compiled display filter program */ 
#ifdef HAVE_LIBPCAP
  gchar       *cfilter;   /* Capture filter string */
  bpf_prog     fcode;     /* Compiled capture filter program */
#endif
  gchar       *sfilter;   /* Search filter string */
  gboolean     sbackward;  /* TRUE if search is backward, FALSE if forward */
  guint8       pd[WTAP_MAX_PACKET_SIZE];  /* Packet data */
  frame_data  *plist;     /* Packet list */
  frame_data  *plist_end; /* Last packet in list */
  frame_data  *first_displayed; /* First frame displayed */
  frame_data  *last_displayed;  /* Last frame displayed */
  column_info  cinfo;    /* Column formatting information */
  frame_data  *current_frame;  /* Frame data for current frame */
  int          current_row;    /* Row in packet display of current frame */
  gboolean     current_frame_is_selected; /* TRUE if that frame is selected */
  proto_tree  *protocol_tree; /* Protocol tree for currently selected packet */
  FILE        *print_fh;  /* File we're printing to */
} capture_file;

int  open_cap_file(char *, gboolean, capture_file *);
void close_cap_file(capture_file *, void *);
int  read_cap_file(capture_file *);
int  start_tail_cap_file(char *, gboolean, capture_file *);
int  continue_tail_cap_file(capture_file *, int);
int  finish_tail_cap_file(capture_file *);
/* size_t read_frame_header(capture_file *); */
int  save_cap_file(char *, capture_file *, gboolean, guint);

int filter_packets(capture_file *cf, gchar *dfilter);
void colorize_packets(capture_file *);
int print_packets(capture_file *cf, print_args_t *print_args);
void change_time_formats(capture_file *);
gboolean find_packet(capture_file *cf, dfilter *sfcode);

typedef enum {
  FOUND_FRAME,		/* found the frame */
  NO_SUCH_FRAME,	/* no frame with that number */
  FRAME_NOT_DISPLAYED	/* frame with that number isn't displayed */
} goto_result_t;
goto_result_t goto_frame(capture_file *cf, guint fnumber);

void select_packet(capture_file *, int);
void unselect_packet(capture_file *);

/* Moves or copies a file. Returns 0 on failure, 1 on success */
int file_mv(char *from, char *to);

/* Copies a file. Returns 0 on failure, 1 on success */
int file_cp(char *from, char *to);

char *file_open_error_message(int, int);
char *file_read_error_message(int);
char *file_write_error_message(int);

#endif /* file.h */
