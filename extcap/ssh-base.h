/* ssh-base.h
 * ssh-base has base utility functions to connect to hosts via ssh
 *
 * Copyright 2016, Dario Lombardo
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

#ifndef __SSHBASE_H__
#define __SSHBASE_H__

#include <libssh/libssh.h>

#define SSH_BASE_OPTIONS \
	{ "remote-host", required_argument, NULL, OPT_REMOTE_HOST}, \
	{ "remote-port", required_argument, NULL, OPT_REMOTE_PORT}, \
	{ "remote-username", required_argument, NULL, OPT_REMOTE_USERNAME}, \
	{ "remote-password", required_argument, NULL, OPT_REMOTE_PASSWORD}, \
	{ "remote-interface", required_argument, NULL, OPT_REMOTE_INTERFACE}, \
	{ "remote-filter", required_argument, NULL, OPT_REMOTE_FILTER}, \
	{ "remote-count", required_argument, NULL, OPT_REMOTE_COUNT}, \
	{ "sshkey", required_argument, NULL, OPT_SSHKEY}, \
	{ "sshkey-passphrase", required_argument, NULL, OPT_SSHKEY_PASSPHRASE}

/* Create a ssh connection using all the possible authentication menthods */
ssh_session create_ssh_connection(const char* hostname, const unsigned int port, const char* username,
	const char* password, const char* sshkey_path, const char* sshkey_passphrase, char** err_info);

/* Write a formatted message in the channel */
int ssh_channel_printf(ssh_channel channel, const char* fmt, ...);

/* Clean the current ssh session and channel. */
void ssh_cleanup(ssh_session* sshs, ssh_channel* channel);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
