/* capture_loop.h
 * Do the low-level work of a capture
 *
 * $Id$
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


/** @file
 *  
 *  Do the low-level work of a capture.
 *
 */

#ifndef __CAPTURE_LOOP_H__
#define __CAPTURE_LOOP_H__

#ifndef _WIN32
/*
 * Get information about libpcap format from "wiretap/libpcap.h".
 * XXX - can we just use pcap_open_offline() to read the pipe?
 */
#include "wiretap/libpcap.h"
#endif

/** Do the low-level work of a capture.
 *  Returns TRUE if it succeeds, FALSE otherwise. */
extern int  capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats);

/** Stop a low-level capture (stops the capture child). */
extern void capture_loop_stop(void);


/*** the following is internal only (should be moved to capture_loop_int.h) ***/


typedef void (*capture_packet_cb_fct)(u_char *, const struct pcap_pkthdr *, const u_char *);


/* moved from capture_loop.c here, so we can combine it (and the related functions) with tethereal */
/* XXX - should be moved back to capture_loop.c */
/* E: capture_loop.c only (Ethereal/dumpcap) T: tethereal only */
typedef struct _loop_data {
  /* common */
  gboolean       go;                    /* TRUE as long as we're supposed to keep capturing */
  int            err;                   /* E: if non-zero, error seen while capturing */
  gint           packet_count;          /* Number of packets we have already captured */
  gint           packet_max;            /* E: Number of packets we're supposed to capture - 0 means infinite */

  jmp_buf        stopenv;               /* T: starting point of loop (jump back this point on SIG...) */

  char          *save_file;             /* T: Name of file to which we're writing */
  capture_packet_cb_fct  packet_cb;     /* callback for a single captured packet */

  /* pcap "input file" */
  pcap_t        *pcap_h;                /* pcap handle */
  gboolean       pcap_err;              /* E: TRUE if error from pcap */

  /* capture pipe (unix only "input file") */
  gboolean       from_cap_pipe;         /* TRUE if we are capturing data from a capture pipe */
#ifndef _WIN32
  struct pcap_hdr cap_pipe_hdr;         /* ? */
  struct pcaprec_modified_hdr cap_pipe_rechdr;  /* ? */
  int            cap_pipe_fd;           /* the file descriptor of the capture pipe */
  gboolean       cap_pipe_modified;     /* TRUE if data in the pipe uses modified pcap headers */
  gboolean       cap_pipe_byte_swapped; /* TRUE if data in the pipe is byte swapped */
  unsigned int   cap_pipe_bytes_to_read;/* Used by cap_pipe_dispatch */
  unsigned int   cap_pipe_bytes_read;   /* Used by cap_pipe_dispatch */
  enum {
         STATE_EXPECT_REC_HDR,
         STATE_READ_REC_HDR,
         STATE_EXPECT_DATA,
         STATE_READ_DATA
       } cap_pipe_state;
  enum { PIPOK, PIPEOF, PIPERR, PIPNEXIST } cap_pipe_err;
#endif

  /* output file */
  FILE          *pdh;
  int            linktype;
  gint           wtap_linktype;
  long           bytes_written;

} loop_data;



/** init the capture filter */
typedef enum {
  INITFILTER_NO_ERROR,
  INITFILTER_BAD_FILTER,
  INITFILTER_OTHER_ERROR
} initfilter_status_t;

extern initfilter_status_t
capture_loop_init_filter(pcap_t *pcap_h, gboolean from_cap_pipe, const gchar * iface, gchar * cfilter);

#ifdef HAVE_LIBPCAP
#ifndef _WIN32
extern int 
cap_pipe_dispatch(loop_data *, guchar *, char *, int);
#endif /* _WIN32 */
#endif

extern gboolean 
capture_loop_open_input(capture_options *capture_opts, loop_data *ld,
                        char *errmsg, size_t errmsg_len,
                        char *secondary_errmsg, size_t secondary_errmsg_len);

extern gboolean
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd, char *errmsg, int errmsg_len);

extern gboolean
capture_loop_init_output(capture_options *capture_opts, int save_file_fd, loop_data *ld, char *errmsg, int errmsg_len);

extern gboolean 
capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close);

/*
 * Routines called by the capture loop code to report things.
 */

/** Report a new capture file having been opened. */
extern void
report_new_capture_file(const char *filename);

/** Report a number of new packets captured. */
extern void
report_packet_count(int packet_count);

/** Report the packet drops once the capture finishes. */
extern void
report_packet_drops(int drops);

/** Report an error in the capture. */
extern void 
report_capture_error(const char *error_msg, const char *secondary_error_msg);

/** Report an error with a capture filter. */
extern void
report_cfilter_error(const char *cfilter, const char *errmsg);


#endif /* capture_loop.h */
