/* capture.c
 * Routines for packet capture windows
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_IO_H
# include <io.h>
#endif

#include <signal.h>
#include <errno.h>

#include <pcap.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include "file.h"
#include "capture.h"
#include "capture_sync.h"
#include "capture_ui_utils.h"
#include "util.h"
#include "pcap-util.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include <epan/prefs.h>
#include "conditions.h"
#include "ringbuffer.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif
#include "ui_util.h"


/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY	0
#endif

/*static gboolean normal_do_capture(capture_options *capture_opts, gboolean is_tempfile);*/
static void stop_capture_signal_handler(int signo);


/* open the output file (temporary/specified name/ringbuffer) */
/* Returns TRUE if the file opened successfully, FALSE otherwise. */
static gboolean
capture_open_output(capture_options *capture_opts, gboolean *is_tempfile) {
  char tmpname[128+1];
  gchar *capfile_name;


  if (capture_opts->save_file != NULL) {
    /* If the Sync option is set, we return to the caller while the capture
     * is in progress.  Therefore we need to take a copy of save_file in
     * case the caller destroys it after we return.
     */
    capfile_name = g_strdup(capture_opts->save_file);
    if (capture_opts->multi_files_on) {
      /* ringbuffer is enabled */
/*      capture_opts->save_file_fd = ringbuf_init(capfile_name,
          (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0);*/
    /* XXX - this is a hack, we need to find a way to move this whole function to capture_loop.c */
      capture_opts->save_file_fd = -1;
      if(capture_opts->save_file != NULL) {
        g_free(capture_opts->save_file);
      }
      capture_opts->save_file = capfile_name;
      *is_tempfile = FALSE;
      return TRUE;
    } else {
      /* Try to open/create the specified file for use as a capture buffer. */
      capture_opts->save_file_fd = open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
				0600);
    }
    *is_tempfile = FALSE;
  } else {
    /* Choose a random name for the temporary capture buffer */
    capture_opts->save_file_fd = create_tempfile(tmpname, sizeof tmpname, "ether");
    capfile_name = g_strdup(tmpname);
    *is_tempfile = TRUE;
  }

  /* did we fail to open the output file? */
  if (capture_opts->save_file_fd == -1) {
    if (*is_tempfile) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	"The temporary file to which the capture would be saved (\"%s\") "
	"could not be opened: %s.", capfile_name, strerror(errno));
    } else {
      if (capture_opts->multi_files_on) {
/*        ringbuf_error_cleanup();*/
      }
      open_failure_alert_box(capfile_name, errno, TRUE);
    }
    g_free(capfile_name);
    return FALSE;
  }

  if(capture_opts->save_file != NULL) {
    g_free(capture_opts->save_file);
  }
  capture_opts->save_file = capfile_name;
  /* capture_opts.save_file is "g_free"ed later, which is equivalent to
     "g_free(capfile_name)". */

  return TRUE;
}


#if 0
/* close the output file (NOT the capture file) */
static void
capture_close_output(capture_options *capture_opts)
{
    if (capture_opts->multi_files_on) {
/*        ringbuf_free();*/
    } else {
        g_free(capture_opts->save_file);
    }
    capture_opts->save_file = NULL;
}
#endif


/* Open a specified file, or create a temporary file, and start a capture
   to the file in question.  */
/* Returns TRUE if the capture starts successfully, FALSE otherwise. */
gboolean
do_capture(capture_options *capture_opts)
{
  gboolean is_tempfile;
  gboolean ret;


  /* open the new output file (temporary/specified name/ringbuffer) */
  if(!capture_open_output(capture_opts, &is_tempfile)) {
    return FALSE;
  }

  /* close the currently loaded capture file */
  cf_close(capture_opts->cf);

  /* We could simply use TRUE for this expression now, this will work for all 
   * captures except for some of the multiple files options, as these capture 
   * options currently cannot be passed through the command line to the 
   * capture child.
   *
   * If this is fixed, we could always use the sync mode, throwing away the 
   * normal mode completely and doing some more cleanup. */
/*  if (TRUE) {*/
/*  if (capture_opts->sync_mode) {*/
    /* sync mode: do the capture in a child process */
    ret = sync_pipe_do_capture(capture_opts, is_tempfile);
    /* capture is still running */
    cf_callback_invoke(cf_cb_live_capture_prepare, capture_opts);
#if 0
  } else {
    /* normal mode: do the capture synchronously */
    cf_callback_invoke(cf_cb_live_capture_prepare, capture_opts);
    ret = normal_do_capture(capture_opts, is_tempfile);
    /* capture is finished here */
  }
#endif

  return ret;
}


/* we've succeeded a capture, try to read it into a new capture file */
gboolean
capture_read(capture_options *capture_opts, gboolean is_tempfile, gboolean drops_known,
guint32 drops)
{
    int err;


    /* Capture succeeded; attempt to read in the capture file. */
    if (cf_open(capture_opts->cf, capture_opts->save_file, is_tempfile, &err) != CF_OK) {
      /* We're not doing a capture any more, so we don't have a save
	 file. */
      return FALSE;
    }

    /* Set the read filter to NULL. */
    /* XXX - this is odd here, try to put it somewhere, where it fits better */
    cf_set_rfcode(capture_opts->cf, NULL);

    /* Get the packet-drop statistics.

       XXX - there are currently no packet-drop statistics stored
       in libpcap captures, and that's what we're reading.

       At some point, we will add support in Wiretap to return
       packet-drop statistics for capture file formats that store it,
       and will make "cf_read()" get those statistics from Wiretap.
       We clear the statistics (marking them as "not known") in
       "cf_open()", and "cf_read()" will only fetch them and mark
       them as known if Wiretap supplies them, so if we get the
       statistics now, after calling "cf_open()" but before calling
       "cf_read()", the values we store will be used by "cf_read()".

       If a future libpcap capture file format stores the statistics,
       we'll put them into the capture file that we write, and will
       thus not have to set them here - "cf_read()" will get them from
       the file and use them. */
    if (drops_known) {
      cf_set_drops_known(capture_opts->cf, TRUE);

      /* XXX - on some systems, libpcap doesn't bother filling in
         "ps_ifdrop" - it doesn't even set it to zero - so we don't
         bother looking at it.

         Ideally, libpcap would have an interface that gave us
         several statistics - perhaps including various interface
         error statistics - and would tell us which of them it
         supplies, allowing us to display only the ones it does. */
      cf_set_drops(capture_opts->cf, drops);
    }
    switch (cf_read(capture_opts->cf)) {

    case CF_READ_OK:
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file. */
      break;

    case CF_READ_ABORTED:
      /* Exit by leaving the main loop, so that any quit functions
         we registered get called. */
      main_window_nested_quit();
      return FALSE;
    }

    /* if we didn't captured even a single packet, close the file again */
    if(cf_packet_count(capture_opts->cf) == 0) {
      simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, 
      "%sNo packets captured!%s\n\n"
      "As no data was captured, closing the %scapture file!",
      simple_dialog_primary_start(), simple_dialog_primary_end(),
      (cf_is_tempfile(capture_opts->cf)) ? "temporary " : "");
      cf_close(capture_opts->cf);
    }
  return TRUE;
}


#if 0
/* start a normal capture session */
static gboolean
normal_do_capture(capture_options *capture_opts, gboolean is_tempfile)
{
    gboolean succeeded;
    gboolean stats_known;
    struct pcap_stat stats;


    /* Not sync mode. */
    succeeded = capture_loop_start(capture_opts, &stats_known, &stats);
    if (capture_opts->quit_after_cap) {
      /* DON'T unlink the save file.  Presumably someone wants it. */
        main_window_exit();
    }
    if (succeeded) {
        /* We succeed in doing the capture, try to read it in. */
        succeeded = capture_read(capture_opts, is_tempfile, stats_known, stats.ps_drop);
    }

    /* wether the capture suceeded or not, we have to close the output file here */
    capture_close_output(capture_opts);
    return succeeded;
}
#endif


static void
stop_capture_signal_handler(int signo _U_)
{
  capture_loop_stop();
}


int  
capture_child_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
/*  gchar *err_msg;*/

  g_assert(capture_opts->capture_child);

#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
    signal(SIGUSR1, stop_capture_signal_handler);
#endif

#if 0
    /* parent must have send us a file descriptor for the opened output file */
    if (capture_opts->save_file_fd == -1) {
      /* send this to the standard output as something our parent
	     should put in an error message box */
      err_msg = g_strdup_printf("%s: \"-W\" flag not specified (internal error)\n", CHILD_NAME);
      sync_pipe_errmsg_to_parent(err_msg);
      g_free(err_msg);
      return FALSE;
    }
#endif

  return capture_loop_start(capture_opts, stats_known, stats);
}

void
capture_stop(capture_options *capture_opts)
{
  /* stop the capture child, if we have one */
  if (!capture_opts->capture_child) {	
    sync_pipe_stop(capture_opts);
  }

  /* stop the capture loop */
  capture_loop_stop();
}

void
capture_kill_child(capture_options *capture_opts)
{
  /* kill the capture child, if we have one */
  if (!capture_opts->capture_child) {	
    sync_pipe_kill(capture_opts);
  }
}


#endif /* HAVE_LIBPCAP */
