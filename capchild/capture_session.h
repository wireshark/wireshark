/* capture_session.h
 * State of a capture session
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

#ifndef __CAPCHILD_CAPTURE_SESSION_H__
#define __CAPCHILD_CAPTURE_SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef _WIN32
#include <sys/types.h>
#include <stdint.h>
#endif

#include "capture_opts.h"

#include <wsutil/processes.h>

#ifdef HAVE_LIBPCAP
/* Current state of capture engine. XXX - differentiate states */
typedef enum {
    CAPTURE_STOPPED,        /**< stopped */
    CAPTURE_PREPARING,      /**< preparing, but still no response from capture child */
    CAPTURE_RUNNING         /**< capture child signalled ok, capture is running now */
} capture_state;

struct _capture_file;
struct _info_data;
/*
 * State of a capture session.
 */
typedef struct _capture_session {
    ws_process_id fork_child;             /**< If not -1, in parent, process ID of child */
    int       fork_child_status;          /**< Child exit status */
#ifdef _WIN32
    int       signal_pipe_write_fd;       /**< the pipe to signal the child */
#endif
    capture_state state;                  /**< current state of the capture engine */
#ifndef _WIN32
    uid_t     owner;                      /**< owner of the cfile */
    gid_t     group;                      /**< group of the cfile */
#endif
    gboolean  session_started;
    guint32   count;                      /**< Total number of frames captured */
    capture_options *capture_opts;        /**< options for this capture */
    struct    _capture_file *cf;          /**< handle to cfile */
    struct _info_data *cap_data_info;          /**< stats for this capture */
} capture_session;

extern void
capture_session_init(capture_session *cap_session, struct _capture_file *cf);
#else

/* dummy is needed because clang throws the error: empty struct has size 0 in C, size 1 in C++ */
typedef struct _capture_session {int dummy;} capture_session;

#endif /* HAVE_LIBPCAP */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPCHILD_CAPTURE_SESSION_H__ */
