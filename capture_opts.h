/* capture_opts.h
 * Capture options (all parameters needed to do the actual capture)
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


/** @file
 *
 *  Capture options (all parameters needed to do the actual capture)
 *
 */

#ifndef __CAPTURE_OPTS_H__
#define __CAPTURE_OPTS_H__

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	    /* for gid_t */
#endif

#include "capture_ifinfo.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Current state of capture engine. XXX - differentiate states */
typedef enum {
    CAPTURE_STOPPED,        /**< stopped */
    CAPTURE_PREPARING,      /**< preparing, but still no response from capture child */
    CAPTURE_RUNNING         /**< capture child signalled ok, capture is running now */
} capture_state;

#ifdef HAVE_PCAP_REMOTE
/* Type of capture source */
typedef enum {
    CAPTURE_IFLOCAL,        /**< Local network interface */
    CAPTURE_IFREMOTE        /**< Remote network interface */
} capture_source;

/* Type of RPCAPD Authentication */
typedef enum {
    CAPTURE_AUTH_NULL,      /**< No authentication */
    CAPTURE_AUTH_PWD        /**< User/password authentication */
} capture_auth;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
/**
 * Method of packet sampling (dropping some captured packets),
 * may require additional integer parameter, marked here as N
 */
typedef enum {
    CAPTURE_SAMP_NONE,      /**< No sampling - capture all packets */
    CAPTURE_SAMP_BY_COUNT,  /**< Counter-based sampling -
                                 capture 1 packet from every N */
    CAPTURE_SAMP_BY_TIMER   /**< Timer-based sampling -
                                 capture no more than 1 packet
                                 in N milliseconds */
} capture_sampling;
#endif

typedef struct interface_options_tag {
    gchar *name;
    gchar *descr;
    gchar *cfilter;
    gboolean has_snaplen;
    int snaplen;
    int linktype;
    gboolean promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    int buffer_size;
#endif
    gboolean monitor_mode;
#ifdef HAVE_PCAP_REMOTE
    capture_source src_type;
    gchar *remote_host;
    gchar *remote_port;
    capture_auth auth_type;
    gchar *auth_username;
    gchar *auth_password;
    gboolean datatx_udp;
    gboolean nocap_rpcap;
    gboolean nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    capture_sampling sampling_method;
    int sampling_param;
#endif
} interface_options;

/** Capture options coming from user interface */
typedef struct capture_options_tag {
    /* general */
    void     *cf;                   /**< handle to cfile (note: untyped handle) */
    GArray   *ifaces;               /**< array of interfaces.
                                         Currently only used by dumpcap. */
    interface_options default_options;
    gboolean saving_to_file;        /**< TRUE if capture is writing to a file */
    gchar    *save_file;            /**< the capture file name */
    gboolean group_read_access;     /**< TRUE is group read permission needs to be set */
    gboolean use_pcapng;            /**< TRUE if file format is pcapng */

    /* GUI related */
    gboolean real_time_mode;        /**< Update list of packets in real time */
    gboolean show_info;             /**< show the info dialog */
    gboolean quit_after_cap;        /**< Makes a "capture only mode". Implies -k */
    gboolean restart;               /**< restart after closing is done */

    /* multiple files (and ringbuffer) */
    gboolean multi_files_on;        /**< TRUE if ring buffer in use */

    gboolean has_file_duration;     /**< TRUE if ring duration specified */
    gint32 file_duration;           /**< Switch file after n seconds */
    gboolean has_ring_num_files;    /**< TRUE if ring num_files specified */
    guint32 ring_num_files;         /**< Number of multiple buffer files */

    /* autostop conditions */
    gboolean has_autostop_files;    /**< TRUE if maximum number of capture files
                                         are specified */
    gint32 autostop_files;          /**< Maximum number of capture files */

    gboolean has_autostop_packets;  /**< TRUE if maximum packet count is
                                         specified */
    int autostop_packets;           /**< Maximum packet count */
    gboolean has_autostop_filesize; /**< TRUE if maximum capture file size
                                         is specified */
    gint32 autostop_filesize;       /**< Maximum capture file size */
    gboolean has_autostop_duration; /**< TRUE if maximum capture duration
                                         is specified */
    gint32 autostop_duration;       /**< Maximum capture duration */

    /* internally used (don't touch from outside) */
    int fork_child;                 /**< If not -1, in parent, process ID of child */
    int fork_child_status;          /**< Child exit status */
#ifdef _WIN32
    int signal_pipe_write_fd;       /**< the pipe to signal the child */
#endif
    capture_state state;            /**< current state of the capture engine */
    gboolean output_to_pipe;        /**< save_file is a pipe (named or stdout) */
#ifndef _WIN32
    uid_t owner;                    /**< owner of the cfile */
    gid_t group;                    /**< group of the cfile */
#endif
} capture_options;

/* initialize the capture_options with some reasonable values */
extern void
capture_opts_init(capture_options *capture_opts, void *cf);

/* set a command line option value */
extern int
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg, gboolean *start_capture);

/* log content of capture_opts */
extern void
capture_opts_log(const char *log_domain, GLogLevelFlags log_level, capture_options *capture_opts);

/* print interface capabilities, including link layer types */
extern void
capture_opts_print_if_capabilities(if_capabilities_t *caps, char *name,
                                   gboolean monitor_mode);

/* print list of interfaces */
extern void
capture_opts_print_interfaces(GList *if_list);

/* trim the snaplen entry */
extern void
capture_opts_trim_snaplen(capture_options *capture_opts, int snaplen_min);

/* trim the ring_num_files entry */
extern void
capture_opts_trim_ring_num_files(capture_options *capture_opts);

/* trim the interface entry */
extern gboolean
capture_opts_trim_iface(capture_options *capture_opts, const char *capture_device);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture_opts.h */
