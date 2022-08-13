/* capture_opts.h
 * Capture options (all parameters needed to do the actual capture)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/** @file
 *
 *  Capture options (all parameters needed to do the actual capture)
 *
 */

#ifndef __CAPTURE_OPTS_H__
#define __CAPTURE_OPTS_H__

#include <sys/types.h>     /* for gid_t */

#include <capture/capture_ifinfo.h>
#include "ringbuffer.h"
#include <wsutil/wslog.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Long options.
 * We do not currently have long options corresponding to all short
 * options; we should probably pick appropriate option names for them.
 *
 * NOTE:
 * for tshark, we're using a leading - in the optstring to prevent getopt()
 * from permuting the argv[] entries, in this case, unknown argv[] entries
 * will be returned as parameters to a dummy-option 1.
 * In short: we must not use 1 here, which is another reason to use
 * values outside the range of ASCII graphic characters.
 */
#define LONGOPT_LIST_TSTAMP_TYPES LONGOPT_BASE_CAPTURE+1
#define LONGOPT_SET_TSTAMP_TYPE   LONGOPT_BASE_CAPTURE+2
#define LONGOPT_COMPRESS_TYPE     LONGOPT_BASE_CAPTURE+3
#define LONGOPT_CAPTURE_TMPDIR    LONGOPT_BASE_CAPTURE+4

/*
 * Options for capturing common to all capturing programs.
 */
#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_A "A:"
#else
#define OPTSTRING_A
#endif

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
#define LONGOPT_BUFFER_SIZE \
    {"buffer-size", ws_required_argument, NULL, 'B'},
#define OPTSTRING_B "B:"
#else
#define LONGOPT_BUFFER_SIZE
#define OPTSTRING_B
#endif

#ifdef HAVE_PCAP_CREATE
#define LONGOPT_MONITOR_MODE {"monitor-mode", ws_no_argument, NULL, 'I'},
#define OPTSTRING_I "I"
#else
#define LONGOPT_MONITOR_MODE
#define OPTSTRING_I
#endif

#define LONGOPT_CAPTURE_COMMON \
    {"autostop",              ws_required_argument, NULL, 'a'}, \
    {"ring-buffer",           ws_required_argument, NULL, 'b'}, \
    LONGOPT_BUFFER_SIZE \
    {"list-interfaces",       ws_no_argument,       NULL, 'D'}, \
    {"interface",             ws_required_argument, NULL, 'i'}, \
    LONGOPT_MONITOR_MODE \
    {"list-data-link-types",  ws_no_argument,       NULL, 'L'}, \
    {"no-promiscuous-mode",   ws_no_argument,       NULL, 'p'}, \
    {"snapshot-length",       ws_required_argument, NULL, 's'}, \
    {"linktype",              ws_required_argument, NULL, 'y'}, \
    {"list-time-stamp-types", ws_no_argument,       NULL, LONGOPT_LIST_TSTAMP_TYPES}, \
    {"time-stamp-type",       ws_required_argument, NULL, LONGOPT_SET_TSTAMP_TYPE}, \
    {"compress-type",         ws_required_argument, NULL, LONGOPT_COMPRESS_TYPE}, \
    {"temp-dir",              ws_required_argument, NULL, LONGOPT_CAPTURE_TMPDIR},


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
    gchar        *remote_host;      /**< Host name or network address for remote capturing */
    gchar        *remote_port;      /**< TCP port of remote RPCAP server */
    capture_auth  auth_type;        /**< Authentication type */
    gchar        *auth_username;    /**< Remote authentication parameters */
    gchar        *auth_password;    /**< Remote authentication parameters */
    gboolean      datatx_udp;
    gboolean      nocap_rpcap;
    gboolean      nocap_local;
};

struct remote_host {
    gchar        *r_host;           /**< Host name or network address for remote capturing */
    gchar        *remote_port;      /**< TCP port of remote RPCAP server */
    capture_auth  auth_type;        /**< Authentication type */
    gchar        *auth_username;    /**< Remote authentication parameters */
    gchar        *auth_password;    /**< Remote authentication parameters */
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
    gchar          *name;
    gchar          *display_name;
    gchar          *friendly_name;
    gchar          *vendor_description;
    guint           type;
    gchar          *addresses;
    gint            no_addresses;
    gchar          *cfilter;
    GList          *links;
    gint            active_dlt;
    gboolean        pmode;
    gboolean        has_snaplen;
    int             snaplen;
    gboolean        local;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    gint            buffer;
#endif
#ifdef HAVE_PCAP_CREATE
    gboolean        monitor_mode_enabled;
    gboolean        monitor_mode_supported;
#endif
#ifdef HAVE_PCAP_REMOTE
    remote_options  remote_opts;
#endif
    guint32         last_packets;
    guint32         packet_diff;
    if_info_t       if_info;
    gboolean        selected;
    gboolean        hidden;
    /* External capture cached data */
    GHashTable     *external_cap_args_settings;
    gchar          *timestamp_type;
} interface_t;

typedef struct link_row_tag {
    gchar *name;
    gint dlt;
} link_row;

typedef struct interface_options_tag {
    gchar            *name;                 /* the name of the interface supplied to libpcap/WinPcap/Npcap to specify the interface */
    gchar            *descr;                /* a more user-friendly description of the interface; may be NULL if none */
    gchar            *hardware;             /* description of the hardware */
    gchar            *display_name;         /* the name displayed in the console and title bar */
    gchar            *ifname;               /* if not null, name to use instead of the interface naem in IDBs */
    gchar            *cfilter;
    gboolean          has_snaplen;
    int               snaplen;
    int               linktype;
    gboolean          promisc_mode;
    interface_type    if_type;
    gchar            *extcap;
    gchar            *extcap_fifo;
    GHashTable       *extcap_args;
    GPid              extcap_pid;           /* pid of running process or WS_INVALID_PID */
    gpointer          extcap_pipedata;
    GString          *extcap_stderr;
    guint             extcap_stdout_watch;
    guint             extcap_stderr_watch;
#ifdef _WIN32
    HANDLE            extcap_pipe_h;
    HANDLE            extcap_control_in_h;
    HANDLE            extcap_control_out_h;
#endif
    gchar            *extcap_control_in;
    gchar            *extcap_control_out;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    int               buffer_size;
#endif
    gboolean          monitor_mode;
#ifdef HAVE_PCAP_REMOTE
    capture_source    src_type;
    gchar            *remote_host;
    gchar            *remote_port;
    capture_auth      auth_type;
    gchar            *auth_username;
    gchar            *auth_password;
    gboolean          datatx_udp;
    gboolean          nocap_rpcap;
    gboolean          nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    capture_sampling  sampling_method;
    int               sampling_param;
#endif
    gchar            *timestamp_type;       /* requested timestamp as string */
    int               timestamp_type_id;    /* Timestamp type to pass to pcap_set_tstamp_type.
                                               only valid if timestamp_type != NULL */
} interface_options;

/** Capture options coming from user interface */
typedef struct capture_options_tag {
    /* general */
    GArray            *ifaces;                /**< the interfaces to use for the
                                                   next capture, entries are of
                                                   type interface_options */
    GArray            *all_ifaces;            /**< all interfaces, entries are
                                                   of type interface_t */
    int                ifaces_err;            /**< if all_ifaces is null, the error
                                                   when it was fetched, if any */
    gchar             *ifaces_err_info;       /**< error string for that error */
    guint              num_selected;

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
    interface_options  default_options;

    gboolean           saving_to_file;        /**< TRUE if capture is writing to a file */
    gchar             *save_file;             /**< the capture file name */
    gboolean           group_read_access;     /**< TRUE is group read permission needs to be set */
    gboolean           use_pcapng;            /**< TRUE if file format is pcapng */

    /* GUI related */
    gboolean           real_time_mode;        /**< Update list of packets in real time */
    gboolean           show_info;             /**< show the info dialog. */
    gboolean           restart;               /**< restart after closing is done */
    gchar             *orig_save_file;        /**< the original capture file name (saved for a restart) */

    /* multiple files (and ringbuffer) */
    gboolean           multi_files_on;        /**< TRUE if ring buffer in use */

    gboolean           has_file_duration;     /**< TRUE if ring duration specified */
    gdouble            file_duration;         /**< Switch file after n seconds */
    gboolean           has_file_interval;     /**< TRUE if ring interval specified */
    gint32             file_interval;         /**< Create time intervals of n seconds */
    gboolean           has_file_packets;      /**< TRUE if ring packet count is
                                                   specified */
    int                file_packets;          /**< Switch file after n packets */
    gboolean           has_ring_num_files;    /**< TRUE if ring num_files specified */
    guint32            ring_num_files;        /**< Number of multiple buffer files */
    gboolean           has_nametimenum;       /**< TRUE if file name has date part before num part  */

    /* autostop conditions */
    gboolean           has_autostop_files;    /**< TRUE if maximum number of capture files
                                                   are specified */
    int                autostop_files;        /**< Maximum number of capture files */

    gboolean           has_autostop_packets;  /**< TRUE if maximum packet count is
                                                   specified */
    int                autostop_packets;      /**< Maximum packet count */
    gboolean           has_autostop_written_packets;  /**< TRUE if maximum packet count is
                                                   specified */
    int                autostop_written_packets;      /**< Maximum packet count */
    gboolean           has_autostop_filesize; /**< TRUE if maximum capture file size
                                                   is specified */
    guint32            autostop_filesize;     /**< Maximum capture file size in kB */
    gboolean           has_autostop_duration; /**< TRUE if maximum capture duration
                                                   is specified */
    gdouble            autostop_duration;     /**< Maximum capture duration */

    gboolean           print_file_names;      /**< TRUE if printing names of completed
                                                   files as we close them */
    gchar             *print_name_to;         /**< output file name */
    gchar             *temp_dir;              /**< temporary directory path */

    /* internally used (don't touch from outside) */
    gboolean           output_to_pipe;        /**< save_file is a pipe (named or stdout) */
    gboolean           capture_child;         /**< hidden option: Wireshark child mode */
    gboolean           stop_after_extcaps;    /**< request dumpcap stop after last extcap */
    gboolean           wait_for_extcap_cbs;   /**< extcaps terminated, waiting for callbacks */
    gchar             *compress_type;         /**< compress type */
    gchar             *closed_msg;            /**< Dumpcap capture closed message */
    guint              extcap_terminate_id;   /**< extcap process termination source ID */
} capture_options;

/* initialize the capture_options with some reasonable values */
extern void
capture_opts_init(capture_options *capture_opts);

/* clean internal structures */
extern void
capture_opts_cleanup(capture_options *capture_opts);

/* set a command line option value */
extern int
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *ws_optarg);

/* log content of capture_opts */
extern void
capture_opts_log(const char *domain, enum ws_log_level level, capture_options *capture_opts);

enum caps_query {
    CAPS_QUERY_LINK_TYPES      = 0x1,
    CAPS_QUERY_TIMESTAMP_TYPES = 0x2
};

/* print interface capabilities, including link layer types */
extern int
capture_opts_print_if_capabilities(if_capabilities_t *caps,
                                   interface_options *interface_opts,
                                   int queries);

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
capture_opts_del_iface(capture_options *capture_opts, guint if_index);

extern void
collect_ifaces(capture_options *capture_opts);

extern void
capture_opts_free_interface_t(interface_t *device);

/* Default capture buffer size in Mbytes. */
#define DEFAULT_CAPTURE_BUFFER_SIZE 2

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_OPTS_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
