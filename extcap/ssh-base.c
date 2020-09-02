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
#include <libssh/callbacks.h>
#include <ws_attributes.h>

static void extcap_log(int priority _U_, const char *function, const char *buffer, void *userdata _U_)
{
	g_debug("[%s] %s", function, buffer);
}

void add_libssh_info(extcap_parameters * extcap_conf)
{
	extcap_base_set_compiled_with(extcap_conf, "libssh version %s", SSH_STRINGIFY(LIBSSH_VERSION));
	extcap_base_set_running_with(extcap_conf, "libssh version %s", ssh_version(0));
}

ssh_session create_ssh_connection(const ssh_params_t* ssh_params, char** err_info)
{
	ssh_session sshs;
	gchar* username = NULL;
	guint port;

	/* Open session and set options */
	sshs = ssh_new();
	if (sshs == NULL) {
		*err_info = g_strdup("Can't create ssh session");
		return NULL;
	}

	if (!ssh_params->host) {
		*err_info = g_strdup("Hostname needed");
		goto failure;
	}

	if (ssh_options_set(sshs, SSH_OPTIONS_HOST, ssh_params->host)) {
		*err_info = g_strdup_printf("Can't set the host: %s", ssh_params->host);
		goto failure;
	}

	/* Load the configurations already present in the system configuration file. */
	/* They will be overwritten by the user-provided configurations. */
	if (ssh_options_parse_config(sshs, NULL) != 0) {
		*err_info = g_strdup("Unable to load the configuration file");
		goto failure;
	}

	if (ssh_params->debug) {
		int debug_level = SSH_LOG_INFO;
		ssh_options_set(sshs, SSH_OPTIONS_LOG_VERBOSITY, &debug_level);
		ssh_set_log_callback(extcap_log);
	}

	if (ssh_params->port != 0) {
		port = ssh_params->port;
		if (ssh_options_set(sshs, SSH_OPTIONS_PORT, &port)) {
			*err_info = g_strdup_printf("Can't set the port: %u", port);
			goto failure;
		}
	}

	if (ssh_params->proxycommand) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PROXYCOMMAND, ssh_params->proxycommand)) {
			*err_info = g_strdup_printf("Can't set the ProxyCommand: %s", ssh_params->proxycommand);
			goto failure;
		}
	}

	if (ssh_params->username) {
		if (ssh_options_set(sshs, SSH_OPTIONS_USER, ssh_params->username)) {
			*err_info = g_strdup_printf("Can't set the username: %s", ssh_params->username);
			goto failure;
		}
	}

	ssh_options_get(sshs, SSH_OPTIONS_USER, &username);
	ssh_options_get_port(sshs, &port);

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Opening ssh connection to %s@%s:%u", username,
		ssh_params->host, port);

	ssh_string_free_char(username);

	/* Connect to server */
	if (ssh_connect(sshs) != SSH_OK) {
		*err_info = g_strdup_printf("Connection error: %s", ssh_get_error(sshs));
		goto failure;
	}

	/* If a public key path has been provided, try to authenticate using it */
	if (ssh_params->sshkey_path) {
		ssh_key pkey = ssh_key_new();
		int ret;

		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using public key in %s...", ssh_params->sshkey_path);
		ret = ssh_pki_import_privkey_file(ssh_params->sshkey_path, ssh_params->sshkey_passphrase, NULL, NULL, &pkey);

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
	if (ssh_params->password) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Connecting using password...");
		if (ssh_userauth_password(sshs, ssh_params->username, ssh_params->password) == SSH_AUTH_SUCCESS) {
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

ssh_params_t* ssh_params_new(void)
{
	return g_new0(ssh_params_t, 1);
}

void ssh_params_free(ssh_params_t* ssh_params)
{
	if (!ssh_params)
		return;
	g_free(ssh_params->host);
	g_free(ssh_params->username);
	g_free(ssh_params->password);
	g_free(ssh_params->sshkey_path);
	g_free(ssh_params->sshkey_passphrase);
	g_free(ssh_params->proxycommand);
	g_free(ssh_params);
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
