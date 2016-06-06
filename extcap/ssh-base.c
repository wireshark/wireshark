/* ssh-base.c
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

#include "config.h"

#include "ssh-base.h"

#include <extcap/extcap-base.h>
#include <log.h>
#include <string.h>

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }

ssh_session create_ssh_connection(const char* hostname, const unsigned int port, const char* username,
	const char* password, const char* sshkey_path, const char* sshkey_passphrase, char** err_info)
{
	ssh_session sshs;

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

	if (port != 0) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PORT, &port)) {
			*err_info = g_strdup_printf("Can't set the port: %d", port);
			goto failure;
		}
	}

	if (!username)
		username = g_get_user_name();

	if (ssh_options_set(sshs, SSH_OPTIONS_USER, username)) {
		*err_info = g_strdup_printf("Can't set the username: %s", username);
		goto failure;
	}

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Opening ssh connection to %s@%s:%u", username, hostname, port);

	/* Connect to server */
	if (ssh_connect(sshs) != SSH_OK) {
		*err_info = g_strdup_printf("Error connecting to %s@%s:%u (%s)", username, hostname, port,
			ssh_get_error(sshs));
		goto failure;
	}

#ifdef HAVE_LIBSSH_USERAUTH_AGENT
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, ("Connecting using ssh-agent...");
	/* Try to authenticate using ssh agent */
	if (ssh_userauth_agent(sshs, NULL) == SSH_AUTH_SUCCESS) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "done");
		return sshs;
	}
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, ("failed");
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
