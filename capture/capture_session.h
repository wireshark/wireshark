/** @file
 *
 * State of a capture session
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPCHILD_CAPTURE_SESSION_H__
#define __CAPCHILD_CAPTURE_SESSION_H__

#ifndef _WIN32
#include <sys/types.h>
#include <stdint.h>
#endif

#include "capture_opts.h"

#include <wsutil/processes.h>

#include "cfile.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_LIBPCAP
/* Current state of capture engine. XXX - differentiate states */
typedef enum {
    CAPTURE_STOPPED,        /**< stopped */
    CAPTURE_PREPARING,      /**< preparing, but still no response from capture child */
    CAPTURE_RUNNING         /**< capture child signalled ok, capture is running now */
} capture_state;

struct _info_data;

/*
 * State of a capture session.
 */
typedef struct _capture_session capture_session;

/*
 * Types of callbacks.
 */

/**
 * Capture child told us we have a new (or the first) capture file.
 */
typedef gboolean (*new_file_fn)(capture_session *cap_session, gchar *new_file);

/**
 * Capture child told us we have new packets to read.
 */
typedef void (*new_packets_fn)(capture_session *cap_session, int to_read);

/**
 * Capture child told us how many dropped packets it counted.
 */
typedef void (*drops_fn)(capture_session *cap_session, guint32 dropped,
                         const char *interface_name);

/**
 * Capture child told us that an error has occurred while starting
 * the capture.
 */
typedef void (*error_fn)(capture_session *cap_session, char *error_msg,
                         char *secondary_error_msg);

/**
 * Capture child told us that an error has occurred while parsing a
 * capture filter when starting/running the capture.
 */
typedef void (*cfilter_error_fn)(capture_session *cap_session, guint i,
                                 const char *error_message);

/**
 * Capture child closed its side of the pipe, report any error and
 * do the required cleanup.
 */
typedef void (*closed_fn)(capture_session *cap_session, gchar *msg);

/*
 * The structure for the session.
 */
struct _capture_session {
    ws_process_id fork_child;             /**< If not WS_INVALID_PID, in parent, process ID of child */
    int       fork_child_status;          /**< Child exit status */
    int       pipe_input_id;              /**< GLib input pipe source ID */
#ifdef _WIN32
    int       sync_pipe_read_fd;          /**< Input pipe descriptor */
    int       signal_pipe_write_fd;       /**< the pipe to signal the child */
#endif
    capture_state state;                  /**< current state of the capture engine */
#ifndef _WIN32
    uid_t     owner;                      /**< owner of the cfile */
    gid_t     group;                      /**< group of the cfile */
#endif
    gboolean  session_will_restart;       /**< Set when session will restart */
    guint32   count;                      /**< Total number of frames captured */
    capture_options *capture_opts;        /**< options for this capture */
    capture_file *cf;                     /**< handle to cfile */
    wtap_rec rec;                         /**< record we're reading packet metadata into */
    Buffer buf;                           /**< Buffer we're reading packet data into */
    struct wtap *wtap;                    /**< current wtap file */
    struct _info_data *cap_data_info;     /**< stats for this capture */

    /*
     * Routines supplied by our caller; we call them back to notify them
     * of various events.
     */
    new_file_fn new_file;
    new_packets_fn new_packets;
    drops_fn drops;
    error_fn error;
    cfilter_error_fn cfilter_error;
    closed_fn closed;
};

extern void
capture_session_init(capture_session *cap_session, capture_file *cf,
                     new_file_fn new_file, new_packets_fn new_packets,
                     drops_fn drops, error_fn error,
                     cfilter_error_fn cfilter_error, closed_fn closed);

void capture_process_finished(capture_session *cap_session);
#else

/* dummy is needed because clang throws the error: empty struct has size 0 in C, size 1 in C++ */
typedef struct _capture_session {int dummy;} capture_session;

#endif /* HAVE_LIBPCAP */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPCHILD_CAPTURE_SESSION_H__ */
