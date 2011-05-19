/* capture_opts.c
 * Routines for capture options setting
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan/packet.h>

#include "capture_opts.h"
#include "ringbuffer.h"
#include "clopts_common.h"
#include "console_io.h"
#include "cmdarg_err.h"

#include "capture_ifinfo.h"
#include "capture-pcap-util.h"
#include <wsutil/file_util.h>

static gboolean capture_opts_output_to_pipe(const char *save_file, gboolean *is_pipe);


void
capture_opts_init(capture_options *capture_opts, void *cf)
{
  capture_opts->cf                              = cf;
  capture_opts->cfilter                         = g_strdup("");     /* No capture filter string specified */
  capture_opts->iface                           = NULL;             /* Default is "pick the first interface" */
  capture_opts->iface_descr                     = NULL;
  capture_opts->ifaces                          = g_array_new(FALSE, FALSE, sizeof(interface_options));
  capture_opts->default_options.name            = NULL;
  capture_opts->default_options.descr           = NULL;
  capture_opts->default_options.cfilter         = g_strdup("");
  capture_opts->default_options.snaplen         = WTAP_MAX_PACKET_SIZE;
  capture_opts->default_options.linktype        = -1;
  capture_opts->default_options.promisc_mode    = TRUE;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  capture_opts->default_options.buffer_size     = 1;                /* 1 MB */
#endif
  capture_opts->default_options.monitor_mode    = FALSE;
#ifdef HAVE_PCAP_REMOTE
  capture_opts->default_options.src_type        = CAPTURE_IFLOCAL;
  capture_opts->default_options.remote_host     = NULL;
  capture_opts->default_options.remote_port     = NULL;
  capture_opts->default_options.auth_type       = CAPTURE_AUTH_NULL;
  capture_opts->default_options.auth_username   = NULL;
  capture_opts->default_options.auth_password   = NULL;
  capture_opts->default_options.datatx_udp      = FALSE;
  capture_opts->default_options.nocap_rpcap     = TRUE;
  capture_opts->default_options.nocap_local     = FALSE;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
  capture_opts->default_options.sampling_method = CAPTURE_SAMP_NONE;
  capture_opts->default_options.sampling_param  = 0;
#endif
#ifdef HAVE_PCAP_REMOTE
  capture_opts->src_type                        = CAPTURE_IFLOCAL;
  capture_opts->remote_host                     = NULL;
  capture_opts->remote_port                     = NULL;
  capture_opts->auth_type                       = CAPTURE_AUTH_NULL;
  capture_opts->auth_username                   = NULL;
  capture_opts->auth_password                   = NULL;
  capture_opts->datatx_udp                      = FALSE;
  capture_opts->nocap_rpcap                     = TRUE;
  capture_opts->nocap_local                     = FALSE;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
  capture_opts->sampling_method                 = CAPTURE_SAMP_NONE;
  capture_opts->sampling_param                  = 0;
#endif
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  capture_opts->buffer_size                     = 1;                /* 1 MB */
#endif
  capture_opts->has_snaplen                     = FALSE;
  capture_opts->snaplen                         = WTAP_MAX_PACKET_SIZE; /* snapshot length - default is
                                                                           infinite, in effect */
  capture_opts->promisc_mode                    = TRUE;             /* promiscuous mode is the default */
  capture_opts->monitor_mode                    = FALSE;
  capture_opts->linktype                        = -1;               /* the default linktype */
  capture_opts->saving_to_file                  = FALSE;
  capture_opts->save_file                       = NULL;
  capture_opts->group_read_access               = FALSE;
  capture_opts->use_pcapng                      = FALSE;            /* the default is pcap */
  capture_opts->real_time_mode                  = TRUE;
  capture_opts->show_info                       = TRUE;
  capture_opts->quit_after_cap                  = FALSE;
  capture_opts->restart                         = FALSE;

  capture_opts->multi_files_on                  = FALSE;
  capture_opts->has_file_duration               = FALSE;
  capture_opts->file_duration                   = 60;               /* 1 min */
  capture_opts->has_ring_num_files              = FALSE;
  capture_opts->ring_num_files                  = RINGBUFFER_MIN_NUM_FILES;

  capture_opts->has_autostop_files              = FALSE;
  capture_opts->autostop_files                  = 1;
  capture_opts->has_autostop_packets            = FALSE;
  capture_opts->autostop_packets                = 0;
  capture_opts->has_autostop_filesize           = FALSE;
  capture_opts->autostop_filesize               = 1024;             /* 1 MB */
  capture_opts->has_autostop_duration           = FALSE;
  capture_opts->autostop_duration               = 60;               /* 1 min */


  capture_opts->fork_child                      = -1;               /* invalid process handle */
#ifdef _WIN32
  capture_opts->signal_pipe_write_fd            = -1;
#endif
  capture_opts->state                           = CAPTURE_STOPPED;
  capture_opts->output_to_pipe                  = FALSE;
#ifndef _WIN32
  capture_opts->owner                           = getuid();
  capture_opts->group                           = getgid();
#endif
}


/* log content of capture_opts */
void
capture_opts_log(const char *log_domain, GLogLevelFlags log_level, capture_options *capture_opts) {
    guint i;

    g_log(log_domain, log_level, "CAPTURE OPTIONS    :");
    g_log(log_domain, log_level, "CFile              : %p", capture_opts->cf);
    g_log(log_domain, log_level, "Filter             : %s", capture_opts->cfilter);

    for (i = 0; i < capture_opts->ifaces->len; i++) {
        interface_options interface_opts;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        g_log(log_domain, log_level, "Interface name[%02d] : %s", i, interface_opts.name);
        g_log(log_domain, log_level, "Interface Descr[%02d]: %s", i, interface_opts.descr);
        g_log(log_domain, log_level, "Capture filter[%02d] : %s", i, interface_opts.cfilter);
        g_log(log_domain, log_level, "Snap length[%02d]    : %d", i, interface_opts.snaplen);
        g_log(log_domain, log_level, "Link Type[%02d]      : %d", i, interface_opts.linktype);
        g_log(log_domain, log_level, "Promiscous Mode[%02d]: %s", i, interface_opts.promisc_mode?"TRUE":"FALSE");
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        g_log(log_domain, log_level, "Buffer size[%02d]    : %d (MB)", i, interface_opts.buffer_size);
#endif
        g_log(log_domain, log_level, "Monitor Mode[%02d]   : %s", i, interface_opts.monitor_mode?"TRUE":"FALSE");
#ifdef HAVE_PCAP_REMOTE
        g_log(log_domain, log_level, "Capture source[%02d] : %s", i,
            interface_opts.src_type == CAPTURE_IFLOCAL ? "Local interface" :
            interface_opts.src_type == CAPTURE_IFREMOTE ? "Remote interface" :
            "Unknown");
        if (interface_opts.src_type == CAPTURE_IFREMOTE) {
            g_log(log_domain, log_level, "Remote host[%02d]    : %s", i, interface_opts.remote_host);
            g_log(log_domain, log_level, "Remote port[%02d]    : %s", i, interface_opts.remote_port);
        }
        g_log(log_domain, log_level, "Authentication[%02d] : %s", i,
            interface_opts.auth_type == CAPTURE_AUTH_NULL ? "Null" :
            interface_opts.auth_type == CAPTURE_AUTH_PWD ? "By username/password" :
            "Unknown");
        if (interface_opts.auth_type == CAPTURE_AUTH_PWD) {
            g_log(log_domain, log_level, "Auth username[%02d]  : %s", i, interface_opts.auth_password);
            g_log(log_domain, log_level, "Auth password[%02d]  : <hidden>", i);
        }
        g_log(log_domain, log_level, "UDP data tfer[%02d]  : %u", i, interface_opts.datatx_udp);
        g_log(log_domain, log_level, "No cap. RPCAP[%02d]  : %u", i, interface_opts.nocap_rpcap);
        g_log(log_domain, log_level, "No cap. local[%02d]  : %u", i, interface_opts.nocap_local);
#endif
#ifdef HAVE_PCAP_SETSAMPLING
        g_log(log_domain, log_level, "Sampling meth.[%02d] : %d", i, interface_opts.sampling_method);
        g_log(log_domain, log_level, "Sampling param.[%02d]: %d", i, interface_opts.sampling_param);
#endif
    }
    g_log(log_domain, log_level, "Interface name[df] : %s", capture_opts->default_options.name);
    g_log(log_domain, log_level, "Interface Descr[df]: %s", capture_opts->default_options.descr);
    g_log(log_domain, log_level, "Capture filter[df] : %s", capture_opts->default_options.cfilter);
    g_log(log_domain, log_level, "Snap length[df]    : %d", capture_opts->default_options.snaplen);
    g_log(log_domain, log_level, "Link Type[df]      : %d", capture_opts->default_options.linktype);
    g_log(log_domain, log_level, "Promiscous Mode[df]: %s", capture_opts->default_options.promisc_mode?"TRUE":"FALSE");
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    g_log(log_domain, log_level, "Buffer size[df]    : %d (MB)", capture_opts->default_options.buffer_size);
#endif
    g_log(log_domain, log_level, "Monitor Mode[df]   : %s", capture_opts->default_options.monitor_mode?"TRUE":"FALSE");
#ifdef HAVE_PCAP_REMOTE
    g_log(log_domain, log_level, "Capture source[df] : %s",
        capture_opts->default_options.src_type == CAPTURE_IFLOCAL ? "Local interface" :
        capture_opts->default_options.src_type == CAPTURE_IFREMOTE ? "Remote interface" :
        "Unknown");
    if (capture_opts->default_options.src_type == CAPTURE_IFREMOTE) {
        g_log(log_domain, log_level, "Remote host[df]    : %s", capture_opts->default_options.remote_host);
        g_log(log_domain, log_level, "Remote port[df]    : %s", capture_opts->default_options.remote_port);
    }
    g_log(log_domain, log_level, "Authentication[df] : %s",
        capture_opts->default_options.auth_type == CAPTURE_AUTH_NULL ? "Null" :
        capture_opts->default_options.auth_type == CAPTURE_AUTH_PWD ? "By username/password" :
        "Unknown");
    if (capture_opts->default_options.auth_type == CAPTURE_AUTH_PWD) {
        g_log(log_domain, log_level, "Auth username[df]  : %s", capture_opts->default_options.auth_password);
        g_log(log_domain, log_level, "Auth password[df]  : <hidden>");
    }
    g_log(log_domain, log_level, "UDP data tfer[df]  : %u", capture_opts->default_options.datatx_udp);
    g_log(log_domain, log_level, "No cap. RPCAP[df]  : %u", capture_opts->default_options.nocap_rpcap);
    g_log(log_domain, log_level, "No cap. local[df]  : %u", capture_opts->default_options.nocap_local);
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    g_log(log_domain, log_level, "Sampling meth. [df]: %d", capture_opts->default_options.sampling_method);
    g_log(log_domain, log_level, "Sampling param.[df]: %d", capture_opts->default_options.sampling_param);
#endif

#ifdef HAVE_PCAP_REMOTE
    g_log(log_domain, log_level, "Capture source     : %s",
        capture_opts->src_type == CAPTURE_IFLOCAL ? "Local interface" :
        capture_opts->src_type == CAPTURE_IFREMOTE ? "Remote interface" :
        "Unknown");
    if (capture_opts->src_type == CAPTURE_IFREMOTE) {
        g_log(log_domain, log_level, "Remote host        : %s", capture_opts->remote_host);
        g_log(log_domain, log_level, "Remote port        : %s", capture_opts->remote_port);
    }
    g_log(log_domain, log_level, "Authentication     : %s",
        capture_opts->auth_type == CAPTURE_AUTH_NULL ? "Null" :
        capture_opts->auth_type == CAPTURE_AUTH_PWD ? "By username/password" :
        "Unknown");
    if (capture_opts->auth_type == CAPTURE_AUTH_PWD) {
        g_log(log_domain, log_level, "Auth username      : %s", capture_opts->auth_password);
        g_log(log_domain, log_level, "Auth password      : <hidden>");
    }
    g_log(log_domain, log_level, "UDP data transfer  : %u", capture_opts->datatx_udp);
    g_log(log_domain, log_level, "No capture RPCAP   : %u", capture_opts->nocap_rpcap);
    g_log(log_domain, log_level, "No capture local   : %u", capture_opts->nocap_local);
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    g_log(log_domain, log_level, "Sampling meth.     : %d", capture_opts->sampling_method);
    g_log(log_domain, log_level, "Sampling param.    : %d", capture_opts->sampling_param);
#endif
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    g_log(log_domain, log_level, "BufferSize         : %u (MB)", capture_opts->buffer_size);
#endif
    g_log(log_domain, log_level, "Interface Name     : %s", capture_opts->iface);
    g_log(log_domain, log_level, "Interface Descr.   : %s", capture_opts->iface_descr);
    g_log(log_domain, log_level, "SnapLen         (%u): %u", capture_opts->has_snaplen, capture_opts->snaplen);
    g_log(log_domain, log_level, "Promisc            : %u", capture_opts->promisc_mode);
    g_log(log_domain, log_level, "LinkType           : %d", capture_opts->linktype);
    g_log(log_domain, log_level, "SavingToFile       : %u", capture_opts->saving_to_file);
    g_log(log_domain, log_level, "SaveFile           : %s", (capture_opts->save_file) ? capture_opts->save_file : "");
    g_log(log_domain, log_level, "GroupReadAccess    : %u", capture_opts->group_read_access);
    g_log(log_domain, log_level, "Fileformat         : %s", (capture_opts->use_pcapng) ? "PCAPNG" : "PCAP");
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
    g_log(log_domain, log_level, "SignalPipeWrite    : %d", capture_opts->signal_pipe_write_fd);
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

  if (strcmp(arg,"files") == 0) {
    capture_opts->has_ring_num_files = TRUE;
    capture_opts->ring_num_files = get_positive_int(p, "number of ring buffer files");
  } else if (strcmp(arg,"filesize") == 0) {
    capture_opts->has_autostop_filesize = TRUE;
    capture_opts->autostop_filesize = get_positive_int(p, "ring buffer filesize");
  } else if (strcmp(arg,"duration") == 0) {
    capture_opts->has_file_duration = TRUE;
    capture_opts->file_duration = get_positive_int(p, "ring buffer duration");
  }

  *colonp = ':';    /* put the colon back */
  return TRUE;
}

#ifdef HAVE_PCAP_SETSAMPLING
/*
 * Given a string of the form "<sampling type>:<value>", as might appear
 * as an argument to a "-m" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_sampling_arguments(capture_options *capture_opts, const char *arg)
{
    gchar *p = NULL, *colonp;

    colonp = strchr(arg, ':');
    if (colonp == NULL)
        return FALSE;

    p = colonp;
    *p++ = '\0';

    while (isspace((guchar)*p))
        p++;
    if (*p == '\0') {
        *colonp = ':';
        return FALSE;
    }

    if (strcmp(arg, "count") == 0) {
        capture_opts->sampling_method = CAPTURE_SAMP_BY_COUNT;
        capture_opts->sampling_param = get_positive_int(p, "sampling count");
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.sampling_method = CAPTURE_SAMP_BY_COUNT;
            interface_opts.sampling_param = get_positive_int(p, "sampling count");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.sampling_method = CAPTURE_SAMP_BY_COUNT;
            capture_opts->default_options.sampling_param = get_positive_int(p, "sampling count");
        }
    } else if (strcmp(arg, "timer") == 0) {
        capture_opts->sampling_method = CAPTURE_SAMP_BY_TIMER;
        capture_opts->sampling_param = get_positive_int(p, "sampling timer");
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.sampling_method = CAPTURE_SAMP_BY_TIMER;
            interface_opts.sampling_param = get_positive_int(p, "sampling timer");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.sampling_method = CAPTURE_SAMP_BY_COUNT;
            capture_opts->default_options.sampling_param = get_positive_int(p, "sampling timer");
        }
    }
    *colonp = ':';
    return TRUE;
}
#endif

#ifdef HAVE_PCAP_REMOTE
/*
 * Given a string of the form "<username>:<password>", as might appear
 * as an argument to a "-A" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_auth_arguments(capture_options *capture_opts, const char *arg)
{
    gchar *p = NULL, *colonp;

    colonp = strchr(arg, ':');
    if (colonp == NULL)
        return FALSE;

    p = colonp;
    *p++ = '\0';

    while (isspace((guchar)*p))
        p++;

    capture_opts->auth_type = CAPTURE_AUTH_PWD;
    capture_opts->auth_username = g_strdup(arg);
    capture_opts->auth_password = g_strdup(p);
    if (capture_opts->ifaces->len > 0) {
        interface_options interface_opts;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
        interface_opts.auth_type = CAPTURE_AUTH_PWD;
        interface_opts.auth_username = g_strdup(arg);
        interface_opts.auth_password = g_strdup(p);
        g_array_append_val(capture_opts->ifaces, interface_opts);
    } else {
        capture_opts->default_options.auth_type = CAPTURE_AUTH_PWD;
        capture_opts->default_options.auth_username = g_strdup(arg);
        capture_opts->default_options.auth_password = g_strdup(p);
    }
    *colonp = ':';
    return TRUE;
}
#endif

static int
capture_opts_add_iface_opt(capture_options *capture_opts, const char *optarg_str_p)
{
    long        adapter_index;
    char        *p;
    GList       *if_list;
    if_info_t   *if_info;
    int         err;
    gchar       *err_str;
    interface_options interface_opts;


    /*
     * If the argument is a number, treat it as an index into the list
     * of adapters, as printed by "tshark -D".
     *
     * This should be OK on UNIX systems, as interfaces shouldn't have
     * names that begin with digits.  It can be useful on Windows, where
     * more than one interface can have the same name.
     */
    adapter_index = strtol(optarg_str_p, &p, 10);
    if (p != NULL && *p == '\0') {
        if (adapter_index < 0) {
            cmdarg_err("The specified adapter index is a negative number");
            return 1;
        }
        if (adapter_index > INT_MAX) {
            cmdarg_err("The specified adapter index is too large (greater than %d)",
                       INT_MAX);
            return 1;
        }
        if (adapter_index == 0) {
            cmdarg_err("There is no interface with that adapter index");
            return 1;
        }
        if_list = capture_interface_list(&err, &err_str);
        if (if_list == NULL) {
            switch (err) {

            case CANT_GET_INTERFACE_LIST:
                cmdarg_err("%s", err_str);
                g_free(err_str);
                break;

            case NO_INTERFACES_FOUND:
                cmdarg_err("There are no interfaces on which a capture can be done");
                break;
            }
            return 2;
        }
        if_info = (if_info_t *)g_list_nth_data(if_list, adapter_index - 1);
        if (if_info == NULL) {
            cmdarg_err("There is no interface with that adapter index");
            return 1;
        }
        capture_opts->iface = g_strdup(if_info->name);
        interface_opts.name = g_strdup(if_info->name);
        /*  We don't set iface_descr here because doing so requires
         *  capture_ui_utils.c which requires epan/prefs.c which is
         *  probably a bit too much dependency for here...
         */
        free_interface_list(if_list);
    } else {
        capture_opts->iface = g_strdup(optarg_str_p);
        interface_opts.name = g_strdup(optarg_str_p);
    }
    if (capture_opts->default_options.descr) {
        interface_opts.descr = g_strdup(capture_opts->default_options.descr);
    } else {
        interface_opts.descr = NULL;
    }
    interface_opts.cfilter = g_strdup(capture_opts->default_options.cfilter);
    interface_opts.snaplen = capture_opts->default_options.snaplen;
    interface_opts.linktype = capture_opts->default_options.linktype;
    interface_opts.promisc_mode = capture_opts->default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    interface_opts.buffer_size = capture_opts->default_options.buffer_size;
#endif
    interface_opts.monitor_mode = capture_opts->default_options.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
    interface_opts.src_type = capture_opts->default_options.src_type;
    if (capture_opts->default_options.remote_host) {
        interface_opts.remote_host = g_strdup(capture_opts->default_options.remote_host);
    } else {
        interface_opts.remote_host = NULL;
    }
    if (capture_opts->default_options.remote_port) {
        interface_opts.remote_port = g_strdup(capture_opts->default_options.remote_port);
    } else {
        interface_opts.remote_port = NULL;
    }
    interface_opts.auth_type = capture_opts->default_options.auth_type;
    if (capture_opts->default_options.auth_username) {
        interface_opts.auth_username = g_strdup(capture_opts->default_options.auth_username);
    } else {
        interface_opts.auth_username = NULL;
    }
    if (capture_opts->default_options.auth_password) {
        interface_opts.auth_password = g_strdup(capture_opts->default_options.auth_password);
    } else {
        interface_opts.auth_password = NULL;
    }
    interface_opts.datatx_udp = capture_opts->default_options.datatx_udp;
    interface_opts.nocap_rpcap = capture_opts->default_options.nocap_rpcap;
    interface_opts.nocap_local = capture_opts->default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    interface_opts.sampling_method = capture_opts->default_options.sampling_method;
    interface_opts.sampling_param  = capture_opts->default_options.sampling_param;
#endif

    g_array_append_val(capture_opts->ifaces, interface_opts);

    return 0;
}

int
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg_str_p, gboolean *start_capture)
{
    int status;

    switch(opt) {
    case 'a':        /* autostop criteria */
        if (set_autostop_criterion(capture_opts, optarg_str_p) == FALSE) {
            cmdarg_err("Invalid or unknown -a flag \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'A':
        if (get_auth_arguments(capture_opts, optarg_str_p) == FALSE) {
            cmdarg_err("Invalid or unknown -A arg \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#endif
    case 'b':        /* Ringbuffer option */
        capture_opts->multi_files_on = TRUE;
        if (get_ring_arguments(capture_opts, optarg_str_p) == FALSE) {
            cmdarg_err("Invalid or unknown -b arg \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    case 'B':        /* Buffer size */
        capture_opts->buffer_size = get_positive_int(optarg_str_p, "buffer size");
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.buffer_size = get_positive_int(optarg_str_p, "buffer size");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.buffer_size = get_positive_int(optarg_str_p, "buffer size");
        }
        break;
#endif
    case 'c':        /* Capture n packets */
        capture_opts->has_autostop_packets = TRUE;
        capture_opts->autostop_packets = get_positive_int(optarg_str_p, "packet count");
        break;
    case 'f':        /* capture filter */
        capture_opts->has_cfilter = TRUE;
        g_free(capture_opts->cfilter);
        capture_opts->cfilter = g_strdup(optarg_str_p);
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            g_free(interface_opts.cfilter);
            interface_opts.cfilter = g_strdup(capture_opts->cfilter);
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            g_free(capture_opts->default_options.cfilter);
            capture_opts->default_options.cfilter = g_strdup(capture_opts->cfilter);
        }
        break;
    case 'H':        /* Hide capture info dialog box */
        capture_opts->show_info = FALSE;
        break;
    case 'i':        /* Use interface x */
        status = capture_opts_add_iface_opt(capture_opts, optarg_str_p);
        if (status != 0) {
            return status;
        }
        break;
#ifdef HAVE_PCAP_CREATE
    case 'I':        /* Capture in monitor mode */
        capture_opts->monitor_mode = TRUE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.monitor_mode = TRUE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.monitor_mode = TRUE;
        }
        break;
#endif
    case 'k':        /* Start capture immediately */
        *start_capture = TRUE;
        break;
    /*case 'l':*/    /* Automatic scrolling in live capture mode */
#ifdef HAVE_PCAP_SETSAMPLING
    case 'm':
        if (get_sampling_arguments(capture_opts, optarg_str_p) == FALSE) {
            cmdarg_err("Invalid or unknown -m arg \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#endif
    case 'n':        /* Use pcapng format */
        capture_opts->use_pcapng = TRUE;
        break;
    case 'p':        /* Don't capture in promiscuous mode */
        capture_opts->promisc_mode = FALSE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.promisc_mode = FALSE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.promisc_mode = FALSE;
        }
        break;
    case 'Q':        /* Quit after capture (just capture to file) */
        capture_opts->quit_after_cap  = TRUE;
        *start_capture   = TRUE;  /*** -Q implies -k !! ***/
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'r':
        capture_opts->nocap_rpcap = FALSE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.nocap_rpcap = FALSE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.nocap_rpcap = FALSE;
        }
        break;
#endif
    case 's':        /* Set the snapshot (capture) length */
        capture_opts->has_snaplen = TRUE;
        capture_opts->snaplen = get_natural_int(optarg_str_p, "snapshot length");
        /*
         * Make a snapshot length of 0 equivalent to the maximum packet
         * length, mirroring what tcpdump does.
         */
        if (capture_opts->snaplen == 0)
            capture_opts->snaplen = WTAP_MAX_PACKET_SIZE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.snaplen = capture_opts->snaplen;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.snaplen = capture_opts->snaplen;
        }
        break;
    case 'S':        /* "Real-Time" mode: used for following file ala tail -f */
        capture_opts->real_time_mode = TRUE;
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'u':
        capture_opts->datatx_udp = TRUE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.datatx_udp = TRUE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.datatx_udp = TRUE;
        }
        break;
#endif
    case 'w':        /* Write to capture file x */
        capture_opts->saving_to_file = TRUE;
        g_free(capture_opts->save_file);
#if defined _WIN32 && GLIB_CHECK_VERSION(2,6,0)
        /* since GLib 2.6, we need to convert filenames to utf8 for Win32 */
        capture_opts->save_file = g_locale_to_utf8(optarg_str_p, -1, NULL, NULL, NULL);
#else
        capture_opts->save_file = g_strdup(optarg_str_p);
#endif
        status = capture_opts_output_to_pipe(capture_opts->save_file, &capture_opts->output_to_pipe);
        return status;
    case 'g':        /* enable group read access on the capture file(s) */
        capture_opts->group_read_access = TRUE;
        break;
    case 'y':        /* Set the pcap data link type */
        capture_opts->linktype = linktype_name_to_val(optarg_str_p);
        if (capture_opts->linktype == -1) {
            cmdarg_err("The specified data link type \"%s\" isn't valid",
                       optarg_str_p);
            return 1;
        }
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.linktype = linktype_name_to_val(optarg_str_p);
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.linktype = linktype_name_to_val(optarg_str_p);
        }
        break;
    default:
        /* the caller is responsible to send us only the right opt's */
        g_assert_not_reached();
    }

    return 0;
}

void
capture_opts_print_if_capabilities(if_capabilities_t *caps, char *name,
                                   gboolean monitor_mode)
{
    GList *lt_entry;
    data_link_info_t *data_link_info;

    if (caps->can_set_rfmon)
        fprintf_stderr("Data link types of interface %s when %sin monitor mode (use option -y to set):\n",
                       name, monitor_mode ? "" : "not ");
    else
        fprintf_stderr("Data link types of interface %s (use option -y to set):\n", name);
    for (lt_entry = caps->data_link_types; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
        data_link_info = (data_link_info_t *)lt_entry->data;
        fprintf_stderr("  %s", data_link_info->name);
        if (data_link_info->description != NULL)
            fprintf_stderr(" (%s)", data_link_info->description);
        else
            fprintf_stderr(" (not supported)");
        fprintf_stderr("\n");
    }
}

/* Print an ASCII-formatted list of interfaces. */
void
capture_opts_print_interfaces(GList *if_list)
{
    int         i;
    GList       *if_entry;
    if_info_t   *if_info;

    i = 1;  /* Interface id number */
    for (if_entry = g_list_first(if_list); if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        fprintf_stderr("%d. %s", i++, if_info->name);

        /* Print the description if it exists */
        if (if_info->description != NULL)
            fprintf_stderr(" (%s)", if_info->description);
        fprintf_stderr("\n");
    }
}


void capture_opts_trim_snaplen(capture_options *capture_opts, int snaplen_min)
{
    guint i;
    interface_options interface_opts;

    if (capture_opts->snaplen < 1)
        capture_opts->snaplen = WTAP_MAX_PACKET_SIZE;
    else if (capture_opts->snaplen < snaplen_min)
        capture_opts->snaplen = snaplen_min;

    for (i = 0; i < capture_opts->ifaces->len; i++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, 0);
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, 0);
        if (interface_opts.snaplen < 1)
            interface_opts.snaplen = WTAP_MAX_PACKET_SIZE;
        else if (interface_opts.snaplen < snaplen_min)
            interface_opts.snaplen = snaplen_min;
        g_array_append_val(capture_opts->ifaces, interface_opts);
    }
}


void capture_opts_trim_ring_num_files(capture_options *capture_opts)
{
    /* Check the value range of the ring_num_files parameter */
    if (capture_opts->ring_num_files > RINGBUFFER_MAX_NUM_FILES) {
        cmdarg_err("Too many ring buffer files (%u). Reducing to %u.\n", capture_opts->ring_num_files, RINGBUFFER_MAX_NUM_FILES);
        capture_opts->ring_num_files = RINGBUFFER_MAX_NUM_FILES;
    } else if (capture_opts->ring_num_files > RINGBUFFER_WARN_NUM_FILES) {
        cmdarg_err("%u is a lot of ring buffer files.\n", capture_opts->ring_num_files);
    }
#if RINGBUFFER_MIN_NUM_FILES > 0
    else if (capture_opts->ring_num_files < RINGBUFFER_MIN_NUM_FILES)
        cmdarg_err("Too few ring buffer files (%u). Increasing to %u.\n", capture_opts->ring_num_files, RINGBUFFER_MIN_NUM_FILES);
        capture_opts->ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
}


gboolean capture_opts_trim_iface(capture_options *capture_opts, const char *capture_device)
{
    GList       *if_list;
    if_info_t   *if_info;
    int         err;
    gchar       *err_str;
    interface_options interface_opts;


    /* Did the user specify an interface to use? */
    if (capture_opts->ifaces->len == 0) {
        /* No - is a default specified in the preferences file? */
        if (capture_device != NULL) {
            /* Yes - use it. */
            capture_opts->iface = g_strdup(capture_device);
            interface_opts.name = g_strdup(capture_device);
            /*  We don't set iface_descr here because doing so requires
             *  capture_ui_utils.c which requires epan/prefs.c which is
             *  probably a bit too much dependency for here...
             */
        } else {
            /* No - pick the first one from the list of interfaces. */
            if_list = capture_interface_list(&err, &err_str);
            if (if_list == NULL) {
                switch (err) {

                case CANT_GET_INTERFACE_LIST:
                    cmdarg_err("%s", err_str);
                    g_free(err_str);
                    break;

                case NO_INTERFACES_FOUND:
                    cmdarg_err("There are no interfaces on which a capture can be done");
                    break;
                }
                return FALSE;
            }
            if_info = (if_info_t *)if_list->data;	/* first interface */
            capture_opts->iface = g_strdup(if_info->name);
            interface_opts.name = g_strdup(if_info->name);
            /*  We don't set iface_descr here because doing so requires
             *  capture_ui_utils.c which requires epan/prefs.c which is
             *  probably a bit too much dependency for here...
             */
            free_interface_list(if_list);
        }
        if (capture_opts->default_options.descr) {
            interface_opts.descr = g_strdup(capture_opts->default_options.descr);
        } else {
            interface_opts.descr = NULL;
        }
        interface_opts.cfilter = g_strdup(capture_opts->default_options.cfilter);
        interface_opts.snaplen = capture_opts->default_options.snaplen;
        interface_opts.linktype = capture_opts->default_options.linktype;
        interface_opts.promisc_mode = capture_opts->default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        interface_opts.buffer_size = capture_opts->default_options.buffer_size;
#endif
        interface_opts.monitor_mode = capture_opts->default_options.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
        interface_opts.src_type = capture_opts->default_options.src_type;
        if (capture_opts->default_options.remote_host) {
            interface_opts.remote_host = g_strdup(capture_opts->default_options.remote_host);
        } else {
            interface_opts.remote_host = NULL;
        }
        if (capture_opts->default_options.remote_port) {
            interface_opts.remote_port = g_strdup(capture_opts->default_options.remote_port);
        } else {
            interface_opts.remote_port = NULL;
        }
        interface_opts.auth_type = capture_opts->default_options.auth_type;
        if (capture_opts->default_options.auth_username) {
            interface_opts.auth_username = g_strdup(capture_opts->default_options.auth_username);
        } else {
            interface_opts.auth_username = NULL;
        }
        if (capture_opts->default_options.auth_password) {
            interface_opts.auth_password = g_strdup(capture_opts->default_options.auth_password);
        } else {
            interface_opts.auth_password = NULL;
        }
        interface_opts.datatx_udp = capture_opts->default_options.datatx_udp;
        interface_opts.nocap_rpcap = capture_opts->default_options.nocap_rpcap;
        interface_opts.nocap_local = capture_opts->default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
        interface_opts.sampling_method = capture_opts->default_options.sampling_method;
        interface_opts.sampling_param  = capture_opts->default_options.sampling_param;
#endif
        g_array_append_val(capture_opts->ifaces, interface_opts);
    }

    return TRUE;
}



#ifndef S_IFIFO
#define S_IFIFO	_S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif

/* copied from filesystem.c */
static int capture_opts_test_for_fifo(const char *path)
{
  ws_statb64 statb;

  if (ws_stat64(path, &statb) < 0)
    return errno;

  if (S_ISFIFO(statb.st_mode))
    return ESPIPE;
  else
    return 0;
}

static gboolean capture_opts_output_to_pipe(const char *save_file, gboolean *is_pipe)
{
  int err;

  *is_pipe = FALSE;

  if (save_file != NULL) {
    /* We're writing to a capture file. */
    if (strcmp(save_file, "-") == 0) {
      /* Writing to stdout. */
      /* XXX - should we check whether it's a pipe?  It's arguably
         silly to do "-w - >output_file" rather than "-w output_file",
         but by not checking we might be violating the Principle Of
         Least Astonishment. */
      *is_pipe = TRUE;
    } else {
      /* not writing to stdout, test for a FIFO (aka named pipe) */
      err = capture_opts_test_for_fifo(save_file);
      switch (err) {

      case ENOENT:      /* it doesn't exist, so we'll be creating it,
                           and it won't be a FIFO */
      case 0:           /* found it, but it's not a FIFO */
        break;

      case ESPIPE:      /* it is a FIFO */
        *is_pipe = TRUE;
        break;

      default:          /* couldn't stat it              */
        break;          /* ignore: later attempt to open */
                        /*  will generate a nice msg     */
      }
    }
  }

  return 0;
}

#endif /* HAVE_LIBPCAP */
