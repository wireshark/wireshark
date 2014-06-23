/* capture_opts.h
 * Capture options (all parameters needed to do the actual capture)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <capchild/capture_ifinfo.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Long options.
 * We do not currently have long options corresponding to all short
 * options; we should probably pick appropriate option names for them.
 *
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 *
 * NOTE:
 * for tshark, we're using a leading - in the optstring to prevent getopt()
 * from permuting the argv[] entries, in this case, unknown argv[] entries
 * will be returned as parameters to a dummy-option 1.
 * In short: we must not use 1 here, which is another reason to use
 * values outside the range of ASCII graphic characters.
 */
#define LONGOPT_NUM_CAP_COMMENT 128

/*
 * Non-capture long-only options should start here, to avoid collision
 * with capture options.
 */
#define MIN_NON_CAPTURE_LONGOPT 129

/*
 * Options for capturing common to all capturing programs.
 */
#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_A "A:"
#else
#define OPTSTRING_A ""
#endif

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define LONGOPT_BUFFER_SIZE \
	{(char *)"buffer-size", required_argument, NULL, 'B'},
#define OPTSTRING_B "B:"
#else
#define LONGOPT_BUFFER_SIZE
#define OPTSTRING_B ""
#endif

#ifdef HAVE_PCAP_CREATE
#define LONGOPT_MONITOR_MODE {(char *)"monitor-mode", no_argument, NULL, 'I'},
#define OPTSTRING_I "I"
#else
#define LONGOPT_MONITOR_MODE
#define OPTSTRING_I ""
#endif

#define LONGOPT_CAPTURE_COMMON \
        {(char *)"capture-comment", required_argument, NULL, LONGOPT_NUM_CAP_COMMENT}, \
        {(char *)"autostop", required_argument, NULL, 'a'}, \
        {(char *)"ring-buffer", required_argument, NULL, 'b'}, \
        LONGOPT_BUFFER_SIZE \
        {(char *)"list-interfaces", no_argument, NULL, 'D'}, \
        {(char *)"interface", required_argument, NULL, 'i'}, \
        LONGOPT_MONITOR_MODE \
        {(char *)"list-data-link-types", no_argument, NULL, 'L'}, \
        {(char *)"no-promiscuous-mode", no_argument, NULL, 'p'}, \
        {(char *)"snapshot-length", required_argument, NULL, 's'}, \
        {(char *)"linktype", required_argument, NULL, 'y'},

#define OPTSTRING_CAPTURE_COMMON \
	 "a:" OPTSTRING_A "b:" OPTSTRING_B "c:Df:i:" OPTSTRING_I "Lps:y:"

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

#ifdef HAVE_PCAP_REMOTE
struct remote_host_info {
    gchar *remote_host;          /**< Host name or network address for remote capturing */
    gchar *remote_port;          /**< TCP port of remote RPCAP server */
    gint auth_type;              /**< Authentication type */
    gchar *auth_username;        /**< Remote authentication parameters */
    gchar *auth_password;        /**< Remote authentication parameters */
    gboolean datatx_udp;
    gboolean nocap_rpcap;
    gboolean nocap_local;
};

typedef struct remote_options_tag {
    capture_source src_type;
    struct remote_host_info remote_host_opts;
#ifdef HAVE_PCAP_SETSAMPLING
    capture_sampling sampling_method;
    int sampling_param;
#endif
} remote_options;
#endif /* HAVE_PCAP_REMOTE */

typedef struct interface_tag {
    gchar *name;
    gchar *display_name;
    gchar *friendly_name;
    guint type;
    gchar *addresses;
    gint no_addresses;
    gchar *cfilter;
    GList *links;
    gint active_dlt;
    gboolean pmode;
    gboolean has_snaplen;
    guint snaplen;
    gboolean local;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    gint buffer;
#endif
#ifdef HAVE_PCAP_CREATE
    gboolean monitor_mode_enabled;
    gboolean monitor_mode_supported;
#endif
#ifdef HAVE_PCAP_REMOTE
    remote_options remote_opts;
#endif
    guint32     last_packets;
    guint32     packet_diff;
    if_info_t   if_info;
    gboolean    selected;
    gboolean    hidden;
    gboolean    locked;
} interface_t;

typedef struct link_row_tag {
    gchar *name;
    gint dlt;
} link_row;

typedef struct interface_options_tag {
    gchar *name; /* the name of the interface provided to winpcap/libpcap to specify the interface */
    gchar *descr;
    gchar *console_display_name; /* the name displayed in the console, also the basis for autonamed pcap filenames */
    gchar *cfilter;
    gboolean has_snaplen;
    int snaplen;
    int linktype;
    gboolean promisc_mode;
    interface_type if_type;
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
    GArray   *ifaces;               /**< array of interfaces.
                                         Currently only used by dumpcap. */
    GArray   *all_ifaces;
    guint    num_selected;

    /*
     * Options to be applied to all interfaces.
     *
     * Some of these can be set from the GUI, others can't; setting
     * the link-layer header type, for example, doesn't necessarily
     * make sense, as different interfaces may support different sets
     * of link-layer header types.
     *
     * Some that can't be set from the GUI can be set from the command
     * line, by specifying them before any interface is specified.
     * This includes the link-layer header type, so if somebody asks
     * for a link-layer header type that an interface on which they're
     * capturing doesn't support, we should report an error and fail
     * to capture.
     *
     * These can be overridden per-interface.
     */
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
    gchar    *orig_save_file;       /**< the original capture file name (saved for a restart) */

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
    guint32 autostop_filesize;      /**< Maximum capture file size */
    gboolean has_autostop_duration; /**< TRUE if maximum capture duration
                                         is specified */
    gint32 autostop_duration;       /**< Maximum capture duration */

    gchar *capture_comment;         /** capture comment to write to the
                                        output file */

    /* internally used (don't touch from outside) */
    gboolean output_to_pipe;        /**< save_file is a pipe (named or stdout) */
    gboolean capture_child;         /**< hidden option: Wireshark child mode */
} capture_options;

/* initialize the capture_options with some reasonable values */
extern void
capture_opts_init(capture_options *capture_opts);

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

/* pick default interface if none was specified */
extern int
capture_opts_default_iface_if_necessary(capture_options *capture_opts,
                                        const char *capture_device);

extern void
collect_ifaces(capture_options *capture_opts);

/* Default capture buffer size in Mbytes. */
#define DEFAULT_CAPTURE_BUFFER_SIZE 2

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture_opts.h */
