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


static void stop_capture_signal_handler(int signo);



/* start a capture */
/* Returns TRUE if the capture starts successfully, FALSE otherwise. */
gboolean
do_capture(capture_options *capture_opts)
{
  gboolean ret;


  /* close the currently loaded capture file */
  cf_close(capture_opts->cf);

  /* try to start the capture child process */
  ret = sync_pipe_do_capture(capture_opts, capture_opts->save_file == NULL);

  if(ret) {
      /* tell callbacks (menu, ...) that capture is running now */
      cf_callback_invoke(cf_cb_live_capture_prepare, capture_opts);
  } else {
      if(capture_opts->save_file != NULL) {
          g_free(capture_opts->save_file);
          capture_opts->save_file = NULL;
      }
  }

  return ret;
}


/* we've succeeded a capture, try to read it into a new capture file */
static gboolean
capture_input_read_all(capture_options *capture_opts, gboolean is_tempfile, gboolean drops_known,
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


/* capture child tells us, we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_options *capture_opts, gchar *new_file)
{
  gboolean is_tempfile;
  int  err;


      /*g_warning("New capture file: %s", new_file);*/

      /* save the new filename */
      if(capture_opts->save_file != NULL) {
        /* we start a new capture file, simply close the old one */
        /* XXX - is it enough to call cf_close here? */
        /* XXX - is it safe to call cf_close even if the file is close before? */
        cf_close(capture_opts->cf);
        g_free(capture_opts->save_file);
        is_tempfile = FALSE;
      } else {
        /* we didn't had a save_file before, must be a tempfile */
        is_tempfile = TRUE;
        cf_set_tempfile(capture_opts->cf, TRUE);
      }
      capture_opts->save_file = g_strdup(new_file);

      /* if we are in sync mode, open the new file */
    if(capture_opts->sync_mode) {
        /* The child process started a capture.
           Attempt to open the capture file and set up to read it. */
        switch(cf_start_tail(capture_opts->cf, capture_opts->save_file, is_tempfile, &err)) {
        case CF_OK:
            break;
        case CF_ERROR:
            /* Don't unlink the save file - leave it around, for debugging
            purposes. */
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
            return FALSE;
            break;
        }
    }

    return TRUE;
}

    
/* capture child tells us, we have new packets to read */
void
capture_input_new_packets(capture_options *capture_opts, int to_read)
{
  int  err;


  if(capture_opts->sync_mode) {
      /* Read from the capture file the number of records the child told us
         it added.
         XXX - do something if this fails? */
      switch (cf_continue_tail(capture_opts->cf, to_read, &err)) {

      case CF_READ_OK:
      case CF_READ_ERROR:
        /* Just because we got an error, that doesn't mean we were unable
           to read any of the file; we handle what we could get from the
           file.

           XXX - abort on a read error? */
        break;

      case CF_READ_ABORTED:
        /* Kill the child capture process; the user wants to exit, and we
           shouldn't just leave it running. */
        capture_kill_child(capture_opts);
        break;
      }
  }
}


/* capture child closed it's side ot the pipe, do the required cleanup */
void
capture_input_closed(capture_options *capture_opts)
{
    int  err;


    if(capture_opts->sync_mode) {
        /* Read what remains of the capture file, and finish the capture.
           XXX - do something if this fails? */
        switch (cf_finish_tail(capture_opts->cf, &err)) {

        case CF_READ_OK:
            if(cf_packet_count(capture_opts->cf) == 0) {
              simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, 
              "%sNo packets captured!%s\n\n"
              "As no data was captured, closing the %scapture file!",
              simple_dialog_primary_start(), simple_dialog_primary_end(),
              cf_is_tempfile(capture_opts->cf) ? "temporary " : "");
              cf_close(capture_opts->cf);
            }
            break;
        case CF_READ_ERROR:
          /* Just because we got an error, that doesn't mean we were unable
             to read any of the file; we handle what we could get from the
             file. */
          break;

        case CF_READ_ABORTED:
          /* Exit by leaving the main loop, so that any quit functions
             we registered get called. */
          main_window_quit();
        }
    } else {
        /* this is a normal mode capture, read in the capture file data */
        capture_input_read_all(capture_opts, cf_is_tempfile(capture_opts->cf), 
            cf_get_drops_known(capture_opts->cf), cf_get_drops(capture_opts->cf));
    }

    /* We're not doing a capture any more, so we don't have a save file. */
    g_assert(capture_opts->save_file);
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;
}


#ifndef _WIN32
static void
capture_child_stop_signal_handler(int signo _U_)
{
  capture_loop_stop();
}
#endif


int  
capture_child_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
  g_assert(capture_opts->capture_child);

#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
    signal(SIGUSR1, capture_child_stop_signal_handler);
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
  sync_pipe_kill(capture_opts);
}


#endif /* HAVE_LIBPCAP */
