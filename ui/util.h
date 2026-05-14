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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Concatenate command-line arguments into a single space-separated string.
 *
 * @param argc     The total argument count (as passed to main()).
 * @param argv     The argument vector (as passed to main()).
 * @param optindex Index of the first argument to include; typically the
 *                 value of @c optind after option parsing is complete.
 * @return A newly allocated string containing the joined arguments,
 *         or NULL if no arguments remain.
 */
char *get_args_as_string(int argc, char **argv, int optindex);

/**
 * @brief Compute the difference between two seconds/microseconds timestamps.
 *
 * @param diffsec  Receives the seconds component of the difference.
 * @param diffusec Receives the microseconds component of the difference.
 * @param sec1     Seconds of the first (later) timestamp.
 * @param usec1    Microseconds of the first (later) timestamp.
 * @param sec2     Seconds of the second (earlier) timestamp.
 * @param usec2    Microseconds of the second (earlier) timestamp.
 */
void compute_timestamp_diff(int *diffsec, int *diffusec,
                            uint32_t sec1, uint32_t usec1, uint32_t sec2, uint32_t usec2);

/**
 * @brief Build a capture filter string matching the current remote connection.
 *
 * - @c SSH_CONNECTION (ssh): \<remote IP\> \<remote port\> \<local IP\> \<local port\>
 * - @c SSH_CLIENT    (ssh): \<remote IP\> \<remote port\> \<local port\>
 * - @c REMOTEHOST    (tcsh, others): \<remote name\>
 * - @c DISPLAY       (X11): [\<remote name\>]:\<display num\>
 * - @c CLIENTNAME    (Terminal Server): \<remote name\>
 *
 * @return A capture filter string for the detected connection, or NULL if
 *         no remote session is detected.
 */
const char *get_conn_cfilter(void);

/**
 * @brief Determine whether the current session is remote.
 *
 * @return true if a remote connection is detected (see get_conn_cfilter()),
 *         false if the session is local.
 */
bool display_is_remote(void);

/** @brief Return the most recently used file-open directory.
 *
 *  @return The path of the last directory in which a file was opened,
 *          or NULL if no file has been opened yet. */
extern const char *get_last_open_dir(void);

/** @brief Set the most recently used file-open directory.
 *
 *  @param dirname The directory path to record as the last opened. */
extern void set_last_open_dir(const char *dirname);

/** @brief Return the initial directory to present in file-open dialogs.
 *
 *  @return The initial directory path for file-open dialogs. */
extern const char *get_open_dialog_initial_dir(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */
