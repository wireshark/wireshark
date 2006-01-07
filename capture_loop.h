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


/*
 * We don't want to do a "select()" on the pcap_t's file descriptor on
 * BSD (because "select()" doesn't work correctly on BPF devices on at
 * least some releases of some flavors of BSD), and we don't want to do
 * it on Windows (because "select()" is something for sockets, not for
 * arbitrary handles).  (Note that "Windows" here includes Cygwin;
 * even in its pretend-it's-UNIX environment, we're using WinPcap, not
 * a UNIX libpcap.)
 *
 * We *do* want to do it on other platforms, as, on other platforms (with
 * the possible exception of Ultrix and Digital UNIX), the read timeout
 * doesn't expire if no packets have arrived, so a "pcap_dispatch()" call
 * will block until packets arrive, causing the UI to hang.
 *
 * XXX - the various BSDs appear to define BSD in <sys/param.h>; we don't
 * want to include it if it's not present on this platform, however.
 */
#if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__) && !defined(_WIN32) && \
    !defined(__CYGWIN__)
# define MUST_DO_SELECT
#endif

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
#ifdef MUST_DO_SELECT
  int            pcap_fd;               /* pcap file descriptor */
#endif

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

  /* wiretap (output file) */
  wtap_dumper   *wtap_pdh;
  gint           wtap_linktype;

} loop_data;



/** init the capture filter */
extern gboolean 
capture_loop_init_filter(pcap_t *pcap_h, gboolean from_cap_pipe, const gchar * iface, gchar * cfilter, char *errmsg, int errmsg_len);

/** Take care of byte order in the libpcap headers read from pipes. */
extern void
cap_pipe_adjust_header(gboolean byte_swapped, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr);

#ifdef HAVE_LIBPCAP
#ifndef _WIN32
extern int 
cap_pipe_open_live(char *, struct pcap_hdr *, loop_data *, char *, int);

extern int 
cap_pipe_dispatch(int, loop_data *, struct pcap_hdr *, \
                struct pcaprec_modified_hdr *, guchar *, char *, int);
#endif /* _WIN32 */
#endif

extern gboolean 
capture_loop_open_input(capture_options *capture_opts, loop_data *ld, char *errmsg, int errmsg_len);

extern gboolean
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd, char *errmsg, int errmsg_len);

extern gboolean
capture_loop_init_wiretap_output(capture_options *capture_opts, int save_file_fd, loop_data *ld, char *errmsg, int errmsg_len);

extern gboolean 
capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close);

#endif /* capture_loop.h */
