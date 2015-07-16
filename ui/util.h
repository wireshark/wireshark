/* util.h
 * Utility definitions
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
void compute_timestamp_diff(gint *diffsec, gint *diffusec,
                            guint32 sec1, guint32 usec1, guint32 sec2, guint32 usec2);

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
 * @return TRUE if we're running remotely, FALSE if local.
 */
gboolean display_is_remote(void);

/** Set the latest opened directory.
 *  Will already be done when using file_selection_new().
 *
 * @param dirname the dirname
 */
extern void set_last_open_dir(const char *dirname);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
