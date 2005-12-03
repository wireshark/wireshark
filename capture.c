/* capture.c
 * Routines for packet capture
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
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
#include "file_util.h"
#include "log.h"



/** 
 * Start a capture.
 *
 * @return TRUE if the capture starts successfully, FALSE otherwise.
 */
gboolean
capture_start(capture_options *capture_opts)
{
  gboolean ret;


  /* close the currently loaded capture file */
  cf_close(capture_opts->cf);

  g_assert(capture_opts->state == CAPTURE_STOPPED);
  capture_opts->state = CAPTURE_PREPARING;

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Start ...");

  /* try to start the capture child process */
  ret = sync_pipe_start(capture_opts);
  if(!ret) {
      if(capture_opts->save_file != NULL) {
          g_free(capture_opts->save_file);
          capture_opts->save_file = NULL;
      }

      capture_opts->state = CAPTURE_STOPPED;
  } else {
      /* the capture child might not respond shortly after bringing it up */
      /* (especially it will block, if no input coming from an input capture pipe (e.g. mkfifo) is coming in) */

      /* to prevent problems, bring the main GUI into "capture mode" right after successfully */
      /* spawn/exec the capture child, without waiting for any response from it */
      cf_callback_invoke(cf_cb_live_capture_prepared, capture_opts);
  }

  return ret;
}


void
capture_stop(capture_options *capture_opts)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Stop ...");

  cf_callback_invoke(cf_cb_live_capture_stopping, capture_opts);

  /* stop the capture child gracefully */
  sync_pipe_stop(capture_opts);
}


void
capture_restart(capture_options *capture_opts)
{
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Restart");

    capture_opts->restart = TRUE;
    capture_stop(capture_opts);
}


void
capture_kill_child(capture_options *capture_opts)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "Capture Kill");

  /* kill the capture child */
  sync_pipe_kill(capture_opts);
}



/* We've succeeded a (non real-time) capture, try to read it into a new capture file */
static gboolean
capture_input_read_all(capture_options *capture_opts, gboolean is_tempfile, gboolean drops_known,
guint32 drops)
{
  int err;


  /* Capture succeeded; attempt to open the capture file. */
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

  /* read in the packet data */
  switch (cf_read(capture_opts->cf)) {

  case CF_READ_OK:
  case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

  case CF_READ_ABORTED:
    /* User wants to quit program. Exit by leaving the main loop, 
       so that any quit functions we registered get called. */
    main_window_nested_quit();
    return FALSE;
  }

  /* if we didn't captured even a single packet, close the file again */
  if(cf_packet_count(capture_opts->cf) == 0 && !capture_opts->restart) {
    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, 
"%sNo packets captured!%s\n"
"\n"
"As no data was captured, closing the %scapture file!\n"
"\n"
"\n"
"Help about capturing can be found at:\n"
"\n"
"       http://wiki.ethereal.com/CaptureSetup"
#ifdef _WIN32
"\n\n"
"Wireless (Wi-Fi/WLAN):\n"
"Try to switch off promiscuous mode in the Capture Options!"
#endif
"",
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


  if(capture_opts->state == CAPTURE_PREPARING) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started!");
  }
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

  g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

  /* free the old filename */
  if(capture_opts->save_file != NULL) {
    /* we start a new capture file, close the old one (if we had one before) */
    /* (we can only have an open capture file in real_time_mode!) */
    if( ((capture_file *) capture_opts->cf)->state != FILE_CLOSED) {
        cf_callback_invoke(cf_cb_live_capture_update_finished, capture_opts->cf);
        cf_finish_tail(capture_opts->cf, &err);
        cf_close(capture_opts->cf);
    }
    g_free(capture_opts->save_file);
    is_tempfile = FALSE;
    cf_set_tempfile(capture_opts->cf, FALSE);
  } else {
    /* we didn't had a save_file before, must be a tempfile */
    is_tempfile = TRUE;
    cf_set_tempfile(capture_opts->cf, TRUE);
  }

  /* save the new filename */
  capture_opts->save_file = g_strdup(new_file);

  /* if we are in real-time mode, open the new file now */
  if(capture_opts->real_time_mode) {
    /* Attempt to open the capture file and set up to read from it. */
       switch(cf_start_tail(capture_opts->cf, capture_opts->save_file, is_tempfile, &err)) {
    case CF_OK:
      break;
    case CF_ERROR:
      /* Don't unlink (delete) the save file - leave it around, 
         for debugging purposes. */
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      return FALSE;
      break;
    }

    cf_callback_invoke(cf_cb_live_capture_update_started, capture_opts);
  } else {
    cf_callback_invoke(cf_cb_live_capture_fixed_started, capture_opts);
  }

  capture_opts->state = CAPTURE_RUNNING;

  return TRUE;
}

    
/* capture child tells us, we have new packets to read */
void
capture_input_new_packets(capture_options *capture_opts, int to_read)
{
  int  err;


  g_assert(capture_opts->save_file);

  if(capture_opts->real_time_mode) {
    /* Read from the capture file the number of records the child told us it added. */
    switch (cf_continue_tail(capture_opts->cf, to_read, &err)) {

    case CF_READ_OK:
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file.

         XXX - abort on a read error? */
         cf_callback_invoke(cf_cb_live_capture_update_continue, capture_opts->cf);
		 /* update the main window, so we get events (e.g. from the stop toolbar button) */
         main_window_update();
      break;

    case CF_READ_ABORTED:
      /* Kill the child capture process; the user wants to exit, and we
         shouldn't just leave it running. */
      capture_kill_child(capture_opts);
      break;
    }
  }
}


/* Capture child told us, how many dropped packets it counted.
 */
void
capture_input_drops(capture_options *capture_opts, int dropped)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "%d packet%s dropped", dropped, plurality(dropped, "", "s"));

  g_assert(capture_opts->state == CAPTURE_RUNNING);

  cf_set_drops_known(capture_opts->cf, TRUE);
  cf_set_drops(capture_opts->cf, dropped);
}


/* Capture child told us, that an error has occurred while starting the capture. */
void
capture_input_error_message(capture_options *capture_opts, char *error_message)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Error message from child: \"%s\"", error_message);

  g_assert(capture_opts->state == CAPTURE_PREPARING);

  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_message);

  /* the capture child will close the sync_pipe, nothing to do for now */
}


/* capture child closed it's side ot the pipe, do the required cleanup */
void
capture_input_closed(capture_options *capture_opts)
{
    int  err;


    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture stopped!");
    g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

    /* if we didn't started the capture, do a fake start */
    /* (happens if we got an error message - we won't get a filename then) */
    if(capture_opts->state == CAPTURE_PREPARING) {
        if(capture_opts->real_time_mode) {
            cf_callback_invoke(cf_cb_live_capture_update_started, capture_opts);
        } else {
            cf_callback_invoke(cf_cb_live_capture_fixed_started, capture_opts);
        }
    }

    if(capture_opts->real_time_mode) {
		cf_read_status_t status;

        /* Read what remains of the capture file. */
        status = cf_finish_tail(capture_opts->cf, &err);

        /* Tell the GUI, we are not doing a capture any more.
		   Must be done after the cf_finish_tail(), so file lengths are displayed 
		   correct. */
        cf_callback_invoke(cf_cb_live_capture_update_finished, capture_opts->cf);

        /* Finish the capture. */
        switch (status) {

        case CF_READ_OK:
            if(cf_packet_count(capture_opts->cf) == 0 && !capture_opts->restart) {
                simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, 
"%sNo packets captured!%s\n"
"\n"
"As no data was captured, closing the %scapture file!\n"
"\n"
"\n"
"Help about capturing can be found at:\n"
"\n"
"       http://wiki.ethereal.com/CaptureSetup"
#ifdef _WIN32
"\n\n"
"Wireless (Wi-Fi/WLAN):\n"
"Try to switch off promiscuous mode in the Capture Options!"
#endif
"",
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
        /* first of all, we are not doing a capture any more */
        cf_callback_invoke(cf_cb_live_capture_fixed_finished, capture_opts->cf);

        /* this is a normal mode capture and if no error happened, read in the capture file data */
        if(capture_opts->save_file != NULL) {
            capture_input_read_all(capture_opts, cf_is_tempfile(capture_opts->cf), 
                cf_get_drops_known(capture_opts->cf), cf_get_drops(capture_opts->cf));
        }
    }

    capture_opts->state = CAPTURE_STOPPED;

    /* if we couldn't open a capture file, there's nothing more for us to do */
    if(capture_opts->save_file == NULL) {
        cf_close(capture_opts->cf);
        return;
    }

    /* does the user wants to restart the current capture? */
    if(capture_opts->restart) {
        capture_opts->restart = FALSE;

        eth_unlink(capture_opts->save_file);

        /* if it was a tempfile, throw away the old filename (so it will become a tempfile again) */
        if(cf_is_tempfile(capture_opts->cf)) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
        }

        /* ... and start the capture again */
        capture_start(capture_opts);
    } else {
        /* We're not doing a capture any more, so we don't have a save file. */
        g_free(capture_opts->save_file);
        capture_opts->save_file = NULL;
    }
}


#endif /* HAVE_LIBPCAP */
