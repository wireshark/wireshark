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

#include <string.h>
#include <ctype.h>

#include <pcap.h>

#include <glib.h>

#include <epan/packet.h>

#include "capture.h"
#include "ringbuffer.h"
#include "clopts_common.h"
#include "cmdarg_err.h"

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
  capture_opts->save_file               = NULL;
  capture_opts->real_time_mode          = TRUE;
  capture_opts->show_info               = TRUE;
  capture_opts->quit_after_cap          = FALSE;
  capture_opts->restart                 = FALSE;

  capture_opts->multi_files_on          = FALSE;
  capture_opts->has_file_duration       = FALSE;
  capture_opts->file_duration           = 60;               /* 1 min */
  capture_opts->has_ring_num_files      = FALSE;
  capture_opts->ring_num_files          = RINGBUFFER_MIN_NUM_FILES;

  capture_opts->has_autostop_files      = FALSE;
  capture_opts->autostop_files          = 1;
  capture_opts->has_autostop_packets    = FALSE;            
  capture_opts->autostop_packets        = 0;
  capture_opts->has_autostop_filesize   = FALSE;
  capture_opts->autostop_filesize       = 1024;             /* 1 MB */
  capture_opts->has_autostop_duration   = FALSE;
  capture_opts->autostop_duration       = 60;               /* 1 min */


  capture_opts->fork_child              = -1;               /* invalid process handle */
#ifdef _WIN32
  capture_opts->signal_pipe_fd          = -1;
#endif
  capture_opts->state                   = CAPTURE_STOPPED;
}


/* log content of capture_opts */
void
capture_opts_log(const char *log_domain, GLogLevelFlags log_level, capture_options *capture_opts) {
    g_log(log_domain, log_level, "CAPTURE OPTIONS    :");
    g_log(log_domain, log_level, "CFile              : 0x%p", capture_opts->cf);
    g_log(log_domain, log_level, "Filter             : %s", capture_opts->cfilter);
    g_log(log_domain, log_level, "Interface          : %s", capture_opts->iface);
#ifdef _WIN32
    g_log(log_domain, log_level, "BufferSize         : %u (MB)", capture_opts->buffer_size);
#endif
    g_log(log_domain, log_level, "SnapLen         (%u): %u", capture_opts->has_snaplen, capture_opts->snaplen);
    g_log(log_domain, log_level, "Promisc            : %u", capture_opts->promisc_mode);
    g_log(log_domain, log_level, "LinkType           : %d", capture_opts->linktype);
    g_log(log_domain, log_level, "SaveFile           : %s", (capture_opts->save_file) ? capture_opts->save_file : "");
    g_log(log_domain, log_level, "RealTimeMode       : %u", capture_opts->real_time_mode);
    g_log(log_domain, log_level, "ShowInfo           : %u", capture_opts->show_info);
    g_log(log_domain, log_level, "QuitAfterCap       : %u", capture_opts->quit_after_cap);

    g_log(log_domain, log_level, "MultiFilesOn       : %u", capture_opts->multi_files_on);
    g_log(log_domain, log_level, "FileDuration    (%u): %u", capture_opts->has_file_duration, capture_opts->file_duration);
    g_log(log_domain, log_level, "RingNumFiles    (%u): %u", capture_opts->has_ring_num_files, capture_opts->ring_num_files);

    g_log(log_domain, log_level, "AutostopFiles   (%u): %u", capture_opts->has_autostop_files, capture_opts->autostop_files);
    g_log(log_domain, log_level, "AutostopPackets (%u): %u", capture_opts->has_autostop_packets, capture_opts->autostop_packets);
    g_log(log_domain, log_level, "AutostopFilesize(%u): %u (KB)", capture_opts->has_autostop_filesize, capture_opts->autostop_filesize);
    g_log(log_domain, log_level, "AutostopDuration(%u): %u", capture_opts->has_autostop_duration, capture_opts->autostop_duration);

    g_log(log_domain, log_level, "ForkChild          : %d", capture_opts->fork_child);
#ifdef _WIN32
    g_log(log_domain, log_level, "SignalPipeFd       : %d", capture_opts->signal_pipe_fd);
#endif
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
  } else if (strcmp(autostoparg,"files") == 0) {
    capture_opts->multi_files_on = TRUE;
    capture_opts->has_autostop_files = TRUE;
    capture_opts->autostop_files = get_positive_int(p,"autostop files");
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
  if (colonp == NULL)
    return TRUE;

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

  if (strcmp(arg,"files") == 0) {
    capture_opts->has_ring_num_files = TRUE;
    capture_opts->ring_num_files = get_natural_int(p, "number of ring buffer files");
  } else if (strcmp(arg,"filesize") == 0) {
    capture_opts->has_autostop_filesize = TRUE;
    capture_opts->autostop_filesize = get_positive_int(p, "ring buffer filesize");
  } else if (strcmp(arg,"duration") == 0) {
    capture_opts->has_file_duration = TRUE;
    capture_opts->file_duration = get_positive_int(p, "ring buffer duration");
  }

  *colonp = ':';	/* put the colon back */
  return TRUE;
}


#ifdef _WIN32
/*
 * Given a string of the form "<pipe name>:<file descriptor>", as might appear
 * as an argument to a "-Z" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_pipe_arguments(capture_options *capture_opts, const char *arg)
{
  gchar *p = NULL, *colonp;
  int pipe_fd;


  colonp = strchr(arg, ':');
  if (colonp == NULL)
    return TRUE;

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

  if (strcmp(arg,"sync") == 0) {
    /* associate stdout with sync pipe */
    pipe_fd = get_natural_int(p, "sync pipe file descriptor");
    if (dup2(pipe_fd, 1) < 0) {
      cmdarg_err("Unable to dup sync pipe handle");
      return FALSE;
    }
  } else if (strcmp(arg,"signal") == 0) {
    /* associate stdin with signal pipe */
    pipe_fd = get_natural_int(p, "signal pipe file descriptor");
    if (dup2(pipe_fd, 0) < 0) {
      cmdarg_err("Unable to dup signal pipe handle");
      return FALSE;
    }
  }

  *colonp = ':';	/* put the colon back */
  return TRUE;
}
#endif


void
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg, gboolean *start_capture)
{
    switch(opt) {
    case 'a':        /* autostop criteria */
        if (set_autostop_criterion(capture_opts, optarg) == FALSE) {
          cmdarg_err("Invalid or unknown -a flag \"%s\"", optarg);
          exit(1);
        }
        break;
    case 'b':        /* Ringbuffer option */
        capture_opts->multi_files_on = TRUE;
        if (get_ring_arguments(capture_opts, optarg) == FALSE) {
          cmdarg_err("Invalid or unknown -b arg \"%s\"", optarg);
          exit(1);
        }
        break;
#ifdef _WIN32
    case 'B':        /* Buffer size */
        capture_opts->buffer_size = get_positive_int(optarg, "buffer size");
        break;
#endif
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
    case 'S':        /* "Real-Time" mode: used for following file ala tail -f */
        capture_opts->real_time_mode = TRUE;
        break;
    case 'w':        /* Write to capture file xxx */
        capture_opts->save_file = g_strdup(optarg);
	    break;
    case 'y':        /* Set the pcap data link type */
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
        capture_opts->linktype = pcap_datalink_name_to_val(optarg);
        if (capture_opts->linktype == -1) {
          cmdarg_err("The specified data link type \"%s\" isn't valid",
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
       if (get_pipe_arguments(capture_opts, optarg) == FALSE) {
          cmdarg_err("Invalid or unknown -Z flag \"%s\"", optarg);
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
