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
	{ "remote-count", ws_required_argument, NULL, OPT_REMOTE_COUNT}, \
	{ "sshkey", ws_required_argument, NULL, OPT_SSHKEY}, \
	{ "sshkey-passphrase", ws_required_argument, NULL, OPT_SSHKEY_PASSPHRASE}, \
	{ "proxycommand", ws_required_argument, NULL, OPT_PROXYCOMMAND}, \
	{ "ssh-sha1", ws_no_argument, NULL, OPT_SSH_SHA1}

#define SSH_BASE_PACKET_OPTIONS \
	SSH_BASE_OPTIONS, \
	{ "remote-interface", ws_required_argument, NULL, OPT_REMOTE_INTERFACE}, \
	{ "remote-filter", ws_required_argument, NULL, OPT_REMOTE_FILTER}

/**
 * @brief Holds the connection parameters required to establish an SSH session for an SSH-based extcap capture.
 */
typedef struct _ssh_params {
    char*    host;               /**< Hostname or IP address of the remote SSH server to connect to. */
    uint16_t port;               /**< TCP port number of the remote SSH server; typically 22. */
    char*    username;           /**< Username to authenticate with on the remote SSH server; NULL to use the current user. */
    char*    password;           /**< Password for password-based SSH authentication; NULL if using key-based authentication. */
    char*    sshkey_path;        /**< Filesystem path to the private key file used for key-based authentication; NULL if using password authentication. */
    char*    sshkey_passphrase;  /**< Passphrase used to decrypt the private key at sshkey_path; NULL if the key is unencrypted. */
    char*    proxycommand;       /**< Shell command used to establish the SSH connection via a proxy or jump host; NULL for a direct connection. */
    bool     ssh_sha1;           /**< True to permit SHA-1 based host key algorithms, which may be required for older SSH servers. */
    int      debug;              /**< Debug verbosity level for SSH session diagnostics; 0 disables debug output. */
} ssh_params_t;

/* Add libssh version information to an extcap_parameters structure */

/**
 * @brief Adds information about the libssh library version to the extcap parameters.
 *
 * @param extcap_conf Pointer to the extcap parameters structure.
 */
void add_libssh_info(extcap_parameters * extcap_conf);

/**
 * @brief Creates an SSH session based on the provided parameters.
 *
 * Create a ssh connection using all the possible authentication methods
 *
 * @param ssh_params Pointer to the SSH parameters structure containing connection details.
 * @param err_info Pointer to a string that will hold error information if the function fails.
 * @return A pointer to the created SSH session, or NULL if an error occurs.
 */
ssh_session create_ssh_connection(const ssh_params_t* ssh_params, char** err_info);

/**
 * @brief Writes a formatted message to an SSH channel.
 *
 * @param channel The SSH channel to write to.
 * @param fmt The format string for the message.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int ssh_channel_printf(ssh_channel channel, const char* fmt, ...);

/* Clean the current ssh session and channel. */

/**
 * @brief Cleans up SSH session and channel resources.
 *
 * This function is responsible for properly closing and freeing the SSH session and channel resources.
 *
 * @param sshs Pointer to the SSH session to be cleaned up.
 * @param channel Pointer to the SSH channel to be closed.
 */
void ssh_cleanup(ssh_session* sshs, ssh_channel* channel);

/* Init the ssh_params_t structure */

/**
 * @brief Create a new SSH parameters structure.
 *
 * @return A pointer to the newly created ssh_params_t structure, or NULL on failure.
 */
ssh_params_t* ssh_params_new(void);

/* Clean the ssh params */

/**
 * @brief Frees the memory allocated for an ssh_params_t structure.
 *
 * @param ssh_params Pointer to the ssh_params_t structure to be freed.
 */
void ssh_params_free(ssh_params_t* ssh_params);

/* Sets the libssh log level to match the ws log level */

/**
 * @brief Set the log level for SSH parameters.
 *
 * @param ssh_params Pointer to the SSH parameters structure.
 * @param level The desired log level from the ws_log_level enumeration.
 */
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
