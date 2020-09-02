/* ssh-base.h
 * ssh-base has base utility functions to connect to hosts via ssh
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SSHBASE_H__
#define __SSHBASE_H__

#include <libssh/libssh.h>

#include <glib.h>

#include <extcap/extcap-base.h>

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define SSH_BASE_OPTIONS \
	{ "remote-host", required_argument, NULL, OPT_REMOTE_HOST}, \
	{ "remote-port", required_argument, NULL, OPT_REMOTE_PORT}, \
	{ "remote-username", required_argument, NULL, OPT_REMOTE_USERNAME}, \
	{ "remote-password", required_argument, NULL, OPT_REMOTE_PASSWORD}, \
	{ "remote-interface", required_argument, NULL, OPT_REMOTE_INTERFACE}, \
	{ "remote-filter", required_argument, NULL, OPT_REMOTE_FILTER}, \
	{ "remote-count", required_argument, NULL, OPT_REMOTE_COUNT}, \
	{ "sshkey", required_argument, NULL, OPT_SSHKEY}, \
	{ "sshkey-passphrase", required_argument, NULL, OPT_SSHKEY_PASSPHRASE}, \
	{ "proxycommand", required_argument, NULL, OPT_PROXYCOMMAND}

typedef struct _ssh_params {
	gchar* host;
	guint16 port;
	gchar* username;
	gchar* password;
	gchar* sshkey_path;
	gchar* sshkey_passphrase;
	gchar* proxycommand;
	gboolean debug;
} ssh_params_t;

/* Add libssh version information to an extcap_parameters structure */
void add_libssh_info(extcap_parameters * extcap_conf);

/* Create a ssh connection using all the possible authentication menthods */
ssh_session create_ssh_connection(const ssh_params_t* ssh_params, char** err_info);

/* Write a formatted message in the channel */
int ssh_channel_printf(ssh_channel channel, const char* fmt, ...);

/* Clean the current ssh session and channel. */
void ssh_cleanup(ssh_session* sshs, ssh_channel* channel);

/* Init the ssh_params_t structure */
ssh_params_t* ssh_params_new(void);

/* Clean the ssh params */
void ssh_params_free(ssh_params_t* ssh_params);

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
