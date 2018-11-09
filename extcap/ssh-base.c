/* ssh-base.c
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

#include "config.h"

#include "ssh-base.h"

#include <extcap/extcap-base.h>
#include <log.h>
#include <string.h>

ssh_session create_ssh_connection(const char* hostname, const unsigned int port, const char* username,
	const char* password, const char* sshkey_path, const char* sshkey_passphrase, const char* proxycommand,
	char** err_info)
{
	ssh_session sshs;
	gchar* user_set = NULL;
	guint port_set;

	/* Open session and set options */
	sshs = ssh_new();
	if (sshs == NULL) {
		*err_info = g_strdup("Can't create ssh session");
		return NULL;
	}

	if (!hostname) {
		*err_info = g_strdup("Hostname needed");
		goto failure;
	}

	if (ssh_options_set(sshs, SSH_OPTIONS_HOST, hostname)) {
		*err_info = g_strdup_printf("Can't set the hostname: %s", hostname);
		goto failure;
	}

	/* Load the configurations already present in the system configuration file. */
	/* They will be overwritten by the user-provided configurations. */
	if (ssh_options_parse_config(sshs, NULL) != 0) {
		*err_info = g_strdup("Unable to load the configuration file");
		goto failure;
	}

	if (port != 0) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PORT, &port)) {
			*err_info = g_strdup_printf("Can't set the port: %d", port);
			goto failure;
		}
	}

	if (proxycommand) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PROXYCOMMAND, proxycommand)) {
			*err_info = g_strdup_printf("Can't set the ProxyCommand: %s", proxycommand);
			goto failure;
		}
	}

	if (username) {
		if (ssh_options_set(sshs, SSH_OPTIONS_USER, username)) {
			*err_info = g_strdup_printf("Can't set the username: %s", username);
			goto failure;
		}
	}

	ssh_options_get(sshs, SSH_OPTIONS_USER, &user_set);
	ssh_options_get_port(sshs, &port_set);

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Opening ssh connection to %s@%s:%u", user_set, hostname, port_set);

	ssh_string_free_char(user_set);

	/* Connect to server */
	if (ssh_connect(sshs) != SSH_OK) {
		*err_info = g_strdup_printf("Connection error: %s", ssh_get_error(sshs));
		goto failure;
	}

#ifdef HAVE_LIBSSH_USERAUTH_AGENT
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using ssh-agent...");
	/* Try to authenticate using ssh agent */
	if (ssh_userauth_agent(sshs, NULL) == SSH_AUTH_SUCCESS) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "done");
		return sshs;
	}
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "failed");
#endif

	/* If a public key path has been provided, try to authenticate using it */
	if (sshkey_path) {
		ssh_key pkey = ssh_key_new();
		int ret;

		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using public key in %s...", sshkey_path);
		ret = ssh_pki_import_privkey_file(sshkey_path, sshkey_passphrase, NULL, NULL, &pkey);

		if (ret == SSH_OK) {
			if (ssh_userauth_publickey(sshs, NULL, pkey) == SSH_AUTH_SUCCESS) {
				g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "done");
				ssh_key_free(pkey);
				return sshs;
			}
		}
		ssh_key_free(pkey);
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "failed (%s)", ssh_get_error(sshs));
	}

	/* Try to authenticate using standard public key */
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using standard public key...");
	if (ssh_userauth_publickey_auto(sshs, NULL, NULL) == SSH_AUTH_SUCCESS) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "done");
		return sshs;
	}
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "failed");

	/* If a password has been provided and all previous attempts failed, try to use it */
	if (password) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using password...");
		if (ssh_userauth_password(sshs, username, password) == SSH_AUTH_SUCCESS) {
			g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "done");
			return sshs;
		}
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "failed");
	}

	*err_info = g_strdup_printf("Can't find a valid authentication. Disconnecting.");

	/* All authentication failed. Disconnect and return */
	ssh_disconnect(sshs);

failure:
	ssh_free(sshs);
	return NULL;
}

int ssh_channel_printf(ssh_channel channel, const char* fmt, ...)
{
	gchar* buf;
	va_list arg;
	int ret = EXIT_SUCCESS;

	va_start(arg, fmt);
	buf = g_strdup_vprintf(fmt, arg);
	if (ssh_channel_write(channel, buf, (guint32)strlen(buf)) == SSH_ERROR)
		ret = EXIT_FAILURE;
	va_end(arg);
	g_free(buf);

	return ret;
}

void ssh_cleanup(ssh_session* sshs, ssh_channel* channel)
{
	if (*channel) {
		ssh_channel_send_eof(*channel);
		ssh_channel_close(*channel);
		ssh_channel_free(*channel);
		*channel = NULL;
	}

	if (*sshs) {
		ssh_disconnect(*sshs);
		ssh_free(*sshs);
		*sshs = NULL;
	}
}

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
