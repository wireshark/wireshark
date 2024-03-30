/** @file
 *
 * Utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Collect command-line arguments as a string consisting of the arguments,
 * separated by spaces.
 */
char *get_args_as_string(int argc, char **argv, int optindex);

/* Compute the difference between two seconds/microseconds time stamps.
 * Beware: we're using nanosecond resolution now and function is currently unused
 */
void compute_timestamp_diff(int *diffsec, int *diffusec,
                            uint32_t sec1, uint32_t usec1, uint32_t sec2, uint32_t usec2);

/* Try to figure out if we're remotely connected, e.g. via ssh or
    Terminal Server, and create a capture filter that matches aspects of the
    connection.  We match the following environment variables:

    SSH_CONNECTION (ssh): <remote IP> <remote port> <local IP> <local port>
    SSH_CLIENT (ssh): <remote IP> <remote port> <local port>
    REMOTEHOST (tcsh, others?): <remote name>
    DISPLAY (x11): [remote name]:<display num>
    CLIENTNAME (terminal server): <remote name>
 */
const char *get_conn_cfilter(void);

/** Check if we're running on a remote connection.
 * @return true if we're running remotely, false if local.
 */
bool display_is_remote(void);

/** Get the latest directory in which a file has been opened.
 *
 * @return the dirname
 */
extern const char *get_last_open_dir(void);

/** Set the latest directory in which a file has been opened.
 *
 * @param dirname the dirname
 */
extern void set_last_open_dir(const char *dirname);

/** Get the initial directory to use in file open dialogs.
 *
 * @return the dirname
 */
extern const char *get_open_dialog_initial_dir(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */
