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

static gboolean normal_do_capture(capture_options *capture_opts, gboolean is_tempfile);
static void stop_capture_signal_handler(int signo);


void
capture_opts_init(capture_options *capture_opts, void *cfile)
{
  capture_opts->cf                      = cfile;
  capture_opts->cfilter		            = g_strdup("");
  capture_opts->iface                   = NULL;
#ifdef _WIN32
  capture_opts->buffer_size             = 1;                /* 1 MB */
#endif
  capture_opts->has_snaplen             = FALSE;
  capture_opts->snaplen                 = MIN_PACKET_SIZE;
  capture_opts->promisc_mode            = TRUE;
  capture_opts->linktype                = -1;               /* the default linktype */
  capture_opts->capture_child           = FALSE;
  capture_opts->save_file               = NULL;
  capture_opts->save_file_fd            = -1;
  capture_opts->sync_mode               = TRUE;
  capture_opts->show_info               = TRUE;
  capture_opts->quit_after_cap          = FALSE;

  capture_opts->multi_files_on          = FALSE;
  capture_opts->has_file_duration       = FALSE;
  capture_opts->file_duration           = 60;               /* 1 min */
  capture_opts->has_ring_num_files      = TRUE;
  capture_opts->ring_num_files          = 2;

  capture_opts->has_autostop_files      = FALSE;
  capture_opts->autostop_files          = 1;
  capture_opts->has_autostop_packets    = FALSE;
  capture_opts->autostop_packets        = 1;
  capture_opts->has_autostop_filesize   = FALSE;
  capture_opts->autostop_filesize       = 1024 * 1024;      /* 1 MB */
  capture_opts->has_autostop_duration   = FALSE;
  capture_opts->autostop_duration       = 60;               /* 1 min */

}

static int
get_natural_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "ethereal: The specified %s \"%s\" isn't a decimal number\n",
	    name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is a negative number\n",
	    name, string);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is too large (greater than %d)\n",
	    name, string, INT_MAX);
    exit(1);
  }
  return number;
}


static int
get_positive_int(const char *string, const char *name)
{
  long number;

  number = get_natural_int(string, name);

  if (number == 0) {
    fprintf(stderr, "ethereal: The specified %s is zero\n",
	    name);
    exit(1);
  }

  return number;
}


/*
 * Given a string of the form "<autostop criterion>:<value>", as might appear
 * as an argument to a "-a" option, parse it and set the criterion in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
set_autostop_criterion(capture_options *capture_opts, const char *autostoparg)
{
  gchar *p, *colonp;

  colonp = strchr(autostoparg, ':');
  if (colonp == NULL)
    return FALSE;

  p = colonp;
  *p++ = '\0';

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace((guchar)*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }
  if (strcmp(autostoparg,"duration") == 0) {
    capture_opts->has_autostop_duration = TRUE;
    capture_opts->autostop_duration = get_positive_int(p,"autostop duration");
  } else if (strcmp(autostoparg,"filesize") == 0) {
    capture_opts->has_autostop_filesize = TRUE;
    capture_opts->autostop_filesize = get_positive_int(p,"autostop filesize");
  } else {
    return FALSE;
  }
  *colonp = ':'; /* put the colon back */
  return TRUE;
}

/*
 * Given a string of the form "<ring buffer file>:<duration>", as might appear
 * as an argument to a "-b" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_ring_arguments(capture_options *capture_opts, const char *arg)
{
  gchar *p = NULL, *colonp;

  colonp = strchr(arg, ':');

  if (colonp != NULL) {
    p = colonp;
    *p++ = '\0';
  }

  capture_opts->ring_num_files = 
    get_natural_int(arg, "number of ring buffer files");

  if (colonp == NULL)
    return TRUE;

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace((guchar)*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }

  capture_opts->has_file_duration = TRUE;
  capture_opts->file_duration = get_positive_int(p,
						      "ring buffer duration");

  *colonp = ':';	/* put the colon back */
  return TRUE;
}


void
capture_opt_add(capture_options *capture_opts, int opt, const char *optarg, gboolean *start_capture)
{
#ifdef _WIN32
    int i;
#endif

    switch(opt) {
    case 'a':        /* autostop criteria */
        if (set_autostop_criterion(capture_opts, optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -a flag \"%s\"\n", optarg);
          exit(1);
        }
        break;
    case 'b':        /* Ringbuffer option */
        capture_opts->multi_files_on = TRUE;
        capture_opts->has_ring_num_files = TRUE;
        if (get_ring_arguments(capture_opts, optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -b arg \"%s\"\n", optarg);
          exit(1);
        }
        break;
    case 'c':        /* Capture xxx packets */
        capture_opts->has_autostop_packets = TRUE;
        capture_opts->autostop_packets = get_positive_int(optarg, "packet count");
        break;
    case 'f':        /* capture filter */
        if (capture_opts->cfilter)
            g_free(capture_opts->cfilter);
        capture_opts->cfilter = g_strdup(optarg);
        break;
    case 'H':        /* Hide capture info dialog box */
        capture_opts->show_info = FALSE;
        break;
    case 'i':        /* Use interface xxx */
        capture_opts->iface = g_strdup(optarg);
        break;
    case 'k':        /* Start capture immediately */
        *start_capture = TRUE;
        break;
    /*case 'l':*/    /* Automatic scrolling in live capture mode */
    case 'p':        /* Don't capture in promiscuous mode */
        capture_opts->promisc_mode = FALSE;
        break;
    case 'Q':        /* Quit after capture (just capture to file) */
        capture_opts->quit_after_cap  = TRUE;
        *start_capture   = TRUE;  /*** -Q implies -k !! ***/
        break;
    case 's':        /* Set the snapshot (capture) length */
        capture_opts->has_snaplen = TRUE;
        capture_opts->snaplen = get_positive_int(optarg, "snapshot length");
        break;
    case 'S':        /* "Sync" mode: used for following file ala tail -f */
        capture_opts->sync_mode = TRUE;
        break;
    case 'w':        /* Write to capture file xxx */
        capture_opts->save_file = g_strdup(optarg);
	    break;
    case 'W':        /* Write to capture file FD xxx */
        capture_opts->save_file_fd = atoi(optarg);
        break;
    case 'y':        /* Set the pcap data link type */
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
        capture_opts->linktype = pcap_datalink_name_to_val(optarg);
        if (capture_opts->linktype == -1) {
          fprintf(stderr, "ethereal: The specified data link type \"%s\" isn't valid\n",
                  optarg);
          exit(1);
        }
#else /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
        /* XXX - just treat it as a number */
        capture_opts->linktype = get_natural_int(optarg, "data link type");
#endif /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
        break;
#ifdef _WIN32
      /* Hidden option supporting Sync mode */
    case 'Z':        /* Write to pipe FD XXX */
        /* associate stdout with pipe */
        i = atoi(optarg);
        if (dup2(i, 1) < 0) {
          fprintf(stderr, "Unable to dup pipe handle\n");
          exit(1);
        }
        break;
#endif /* _WIN32 */
    default:
        /* the caller is responsible to send us only the right opt's */
        g_assert_not_reached();
    }
}

/* open the output file (temporary/specified name/ringbuffer) and close the old one */
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
do_capture(capture_options *capture_opts)
{
  gboolean is_tempfile;
  gboolean ret;
  gchar *title;

  /* open the output file (temporary/specified name/ringbuffer) and close the old one */
  if(!capture_open_output(capture_opts, &is_tempfile)) {
    return FALSE;
  }

  title = g_strdup_printf("%s: Capturing - Ethereal",
                          get_interface_descriptive_name(capture_opts->iface));
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
capture_kill_child(capture_options *capture_opts)
{
  if (capture_opts->sync_mode) {	
    sync_pipe_kill(capture_opts);
  }
}


#endif /* HAVE_LIBPCAP */
