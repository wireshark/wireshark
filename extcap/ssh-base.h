/** @file
 *
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
	{ "remote-host", ws_required_argument, NULL, OPT_REMOTE_HOST}, \
	{ "remote-port", ws_required_argument, NULL, OPT_REMOTE_PORT}, \
	{ "remote-username", ws_required_argument, NULL, OPT_REMOTE_USERNAME}, \
	{ "remote-password", ws_required_argument, NULL, OPT_REMOTE_PASSWORD}, \
	{ "remote-interface", ws_required_argument, NULL, OPT_REMOTE_INTERFACE}, \
	{ "remote-filter", ws_required_argument, NULL, OPT_REMOTE_FILTER}, \
	{ "remote-count", ws_required_argument, NULL, OPT_REMOTE_COUNT}, \
	{ "sshkey", ws_required_argument, NULL, OPT_SSHKEY}, \
	{ "sshkey-passphrase", ws_required_argument, NULL, OPT_SSHKEY_PASSPHRASE}, \
	{ "proxycommand", ws_required_argument, NULL, OPT_PROXYCOMMAND}, \
	{ "ssh-sha1", ws_no_argument, NULL, OPT_SSH_SHA1}

typedef struct _ssh_params {
	char* host;
	uint16_t port;
	char* username;
	char* password;
	char* sshkey_path;
	char* sshkey_passphrase;
	char* proxycommand;
	bool ssh_sha1;
	int debug;
} ssh_params_t;

/* Add libssh version information to an extcap_parameters structure */
void add_libssh_info(extcap_parameters * extcap_conf);

/* Create a ssh connection using all the possible authentication methods */
ssh_session create_ssh_connection(const ssh_params_t* ssh_params, char** err_info);

/* Write a formatted message in the channel */
int ssh_channel_printf(ssh_channel channel, const char* fmt, ...);

/* Clean the current ssh session and channel. */
void ssh_cleanup(ssh_session* sshs, ssh_channel* channel);

/* Init the ssh_params_t structure */
ssh_params_t* ssh_params_new(void);

/* Clean the ssh params */
void ssh_params_free(ssh_params_t* ssh_params);

/* Sets the libssh log level to match the ws log level */
void ssh_params_set_log_level(ssh_params_t* ssh_params, enum ws_log_level level);

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
