/* capture_opts.c
 * Routines for capture options setting
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

#ifdef HAVE_IO_H
# include <io.h>
#endif

#include <pcap.h>

#include <glib.h>

#include <epan/packet.h>

#include "capture.h"
#include "ringbuffer.h"


void
capture_opts_init(capture_options *capture_opts, void *cfile)
{
  capture_opts->cf                      = cfile;            
  capture_opts->cfilter		            = g_strdup("");     /* No capture filter string specified */
  capture_opts->iface                   = NULL;             /* Default is "pick the first interface" */
#ifdef _WIN32
  capture_opts->buffer_size             = 1;                /* 1 MB */
#endif
  capture_opts->has_snaplen             = FALSE;
  capture_opts->snaplen                 = WTAP_MAX_PACKET_SIZE; /* snapshot length - default is
                                                                    infinite, in effect */
  capture_opts->promisc_mode            = TRUE;             /* promiscuous mode is the default */
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
  capture_opts->has_ring_num_files      = FALSE;
  capture_opts->ring_num_files          = RINGBUFFER_MIN_NUM_FILES;

  capture_opts->has_autostop_files      = FALSE;
  capture_opts->autostop_files          = 1;
  capture_opts->has_autostop_packets    = FALSE;            
  capture_opts->autostop_packets        = 1;
  capture_opts->has_autostop_filesize   = FALSE;
  capture_opts->autostop_filesize       = 1024 * 1024;      /* 1 MB */
  capture_opts->has_autostop_duration   = FALSE;
  capture_opts->autostop_duration       = 60;               /* 1 min */


  capture_opts->fork_child              = -1;               /* invalid process handle */
}

static int
get_natural_int(const char *appname, const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "%s: The specified %s \"%s\" isn't a decimal number\n",
	    appname, name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "%s: The specified %s \"%s\" is a negative number\n",
	    appname, name, string);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "%s: The specified %s \"%s\" is too large (greater than %d)\n",
	    appname, name, string, INT_MAX);
    exit(1);
  }
  return number;
}


static int
get_positive_int(const char *appname, const char *string, const char *name)
{
  long number;

  number = get_natural_int(appname, string, name);

  if (number == 0) {
    fprintf(stderr, "%s: The specified %s is zero\n",
	    appname, name);
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
set_autostop_criterion(capture_options *capture_opts, const char *appname, const char *autostoparg)
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
    capture_opts->autostop_duration = get_positive_int(appname, p,"autostop duration");
  } else if (strcmp(autostoparg,"filesize") == 0) {
    capture_opts->has_autostop_filesize = TRUE;
    capture_opts->autostop_filesize = get_positive_int(appname, p,"autostop filesize");
  } else if (strcmp(autostoparg,"files") == 0) {
    capture_opts->multi_files_on = TRUE;
    capture_opts->has_autostop_files = TRUE;
    capture_opts->autostop_files = get_positive_int(appname, p,"autostop files");
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
get_ring_arguments(capture_options *capture_opts, const char *appname, const char *arg)
{
  gchar *p = NULL, *colonp;

  colonp = strchr(arg, ':');

  if (colonp != NULL) {
    p = colonp;
    *p++ = '\0';
  }

  capture_opts->ring_num_files = 
    get_natural_int(appname, arg, "number of ring buffer files");

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
  capture_opts->file_duration = get_positive_int(appname, p,
						      "ring buffer duration");

  *colonp = ':';	/* put the colon back */
  return TRUE;
}


void
capture_opts_add_opt(capture_options *capture_opts, const char *appname, int opt, const char *optarg, gboolean *start_capture)
{
#ifdef _WIN32
    int i;
#endif

    switch(opt) {
    case 'a':        /* autostop criteria */
        if (set_autostop_criterion(capture_opts, appname, optarg) == FALSE) {
          fprintf(stderr, "%s: Invalid or unknown -a flag \"%s\"\n", appname, optarg);
          exit(1);
        }
        break;
    case 'b':        /* Ringbuffer option */
        capture_opts->multi_files_on = TRUE;
        capture_opts->has_ring_num_files = TRUE;
        if (get_ring_arguments(capture_opts, appname, optarg) == FALSE) {
          fprintf(stderr, "%s: Invalid or unknown -b arg \"%s\"\n", appname, optarg);
          exit(1);
        }
        break;
    case 'c':        /* Capture xxx packets */
        capture_opts->has_autostop_packets = TRUE;
        capture_opts->autostop_packets = get_positive_int(appname, optarg, "packet count");
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
        capture_opts->snaplen = get_positive_int(appname, optarg, "snapshot length");
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
          fprintf(stderr, "%s: The specified data link type \"%s\" isn't valid\n",
                  appname, optarg);
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
          fprintf(stderr, "%s: Unable to dup pipe handle\n", appname);
          exit(1);
        }
        break;
#endif /* _WIN32 */
    default:
        /* the caller is responsible to send us only the right opt's */
        g_assert_not_reached();
    }
}

#endif /* HAVE_LIBPCAP */