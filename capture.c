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

/* With MSVC and a libethereal.dll this file needs to import some variables 
   in a special way. Therefore _NEED_VAR_IMPORT_ is defined. */
#define _NEED_VAR_IMPORT_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <stdlib.h>
#include <string.h>

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

static gboolean normal_do_capture(capture_options *capture_opts, gboolean is_tempfile);
static void stop_capture_signal_handler(int signo);


/* open the output file (temporary/specified name/ringbuffer) and close the old one */
/* Returns TRUE if the file opened successfully, FALSE otherwise. */
static gboolean
capture_open_output(capture_options *capture_opts, const char *save_file, gboolean *is_tempfile) {
  char tmpname[128+1];
  gchar *capfile_name;


  if (save_file != NULL) {
    /* If the Sync option is set, we return to the caller while the capture
     * is in progress.  Therefore we need to take a copy of save_file in
     * case the caller destroys it after we return.
     */
    capfile_name = g_strdup(save_file);
    if (capture_opts->multi_files_on) {
      /* ringbuffer is enabled */
      capture_opts->save_file_fd = ringbuf_init(capfile_name,
          (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0);
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
    if (is_tempfile) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	"The temporary file to which the capture would be saved (\"%s\")"
	"could not be opened: %s.", capfile_name, strerror(errno));
    } else {
      if (capture_opts->multi_files_on) {
        ringbuf_error_cleanup();
      }
      open_failure_alert_box(capfile_name, errno, TRUE);
    }
    g_free(capfile_name);
    return FALSE;
  }

  /* close the old file */
  cf_close(capture_opts->cf);
  g_assert(capture_opts->save_file == NULL);
  capture_opts->save_file = capfile_name;
  /* capture_opts.save_file is "g_free"ed later, which is equivalent to
     "g_free(capfile_name)". */

  return TRUE;
}


/* Open a specified file, or create a temporary file, and start a capture
   to the file in question.  */
/* Returns TRUE if the capture starts successfully, FALSE otherwise. */
gboolean
do_capture(capture_options *capture_opts, const char *save_file)
{
  gboolean is_tempfile;
  gboolean ret;
  gchar *title;

  /* open the output file (temporary/specified name/ringbuffer) and close the old one */
  if(!capture_open_output(capture_opts, save_file, &is_tempfile)) {
    return FALSE;
  }

  title = g_strdup_printf("%s: Capturing - Ethereal",
                          get_interface_descriptive_name(cf_get_iface(capture_opts->cf)));
  if (capture_opts->sync_mode) {	
    /* sync mode: do the capture in a child process */
    ret = sync_pipe_do_capture(capture_opts, is_tempfile);
    /* capture is still running */
    set_main_window_name(title);
  } else {
    /* normal mode: do the capture synchronously */
    set_main_window_name(title);
    ret = normal_do_capture(capture_opts, is_tempfile);
    /* capture is finished here */
  }
  g_free(title);

  return ret;
}


/* start a normal capture session */
static gboolean
normal_do_capture(capture_options *capture_opts, gboolean is_tempfile)
{
    int capture_succeeded;
    gboolean stats_known;
    struct pcap_stat stats;
    int err;

    /* Not sync mode. */
    capture_succeeded = capture_start(capture_opts, &stats_known, &stats);
    if (capture_opts->quit_after_cap) {
      /* DON'T unlink the save file.  Presumably someone wants it. */
        main_window_exit();
    }
    if (!capture_succeeded) {
      /* We didn't succeed in doing the capture, so we don't have a save
	 file. */
      if (capture_opts->multi_files_on) {
	ringbuf_free();
      } else {
	g_free(capture_opts->save_file);
      }
      capture_opts->save_file = NULL;
      return FALSE;
    }
    /* Capture succeeded; attempt to read in the capture file. */
    if (cf_open(capture_opts->cf, capture_opts->save_file, is_tempfile, &err) != CF_OK) {
      /* We're not doing a capture any more, so we don't have a save
	 file. */
      if (capture_opts->multi_files_on) {
	ringbuf_free();
      } else {
	g_free(capture_opts->save_file);
      }
      capture_opts->save_file = NULL;
      return FALSE;
    }

    /* Set the read filter to NULL. */
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
    if (stats_known) {
      cf_set_drops_known(capture_opts->cf, TRUE);

      /* XXX - on some systems, libpcap doesn't bother filling in
         "ps_ifdrop" - it doesn't even set it to zero - so we don't
         bother looking at it.

         Ideally, libpcap would have an interface that gave us
         several statistics - perhaps including various interface
         error statistics - and would tell us which of them it
         supplies, allowing us to display only the ones it does. */
      cf_set_drops(capture_opts->cf, stats.ps_drop);
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

    /* We're not doing a capture any more, so we don't have a save
       file. */
    if (capture_opts->multi_files_on) {
      ringbuf_free();
    } else {
      g_free(capture_opts->save_file);
    }
    capture_opts->save_file = NULL;

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


static void
stop_capture_signal_handler(int signo _U_)
{
  capture_loop_stop();
}


int  
capture_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
  if (capture_opts->capture_child)
    signal(SIGUSR1, stop_capture_signal_handler);
#endif

  return capture_loop_start(capture_opts, stats_known, stats);
}

void
capture_stop(capture_options *capture_opts)
{

  if (capture_opts->sync_mode) {	
    sync_pipe_stop(capture_opts);
  }
    
  capture_loop_stop();
}

void
kill_capture_child(capture_options *capture_opts)
{
  if (capture_opts->sync_mode) {	
    sync_pipe_kill(capture_opts);
  }
}


#endif /* HAVE_LIBPCAP */
