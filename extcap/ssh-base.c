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
#define WS_LOG_DOMAIN LOG_DOMAIN_EXTCAP

#include "ssh-base.h"

#include <extcap/extcap-base.h>
#include <string.h>
#include <libssh/callbacks.h>
#include <ws_attributes.h>
#include <wsutil/wslog.h>

/*
 * The unreleased 0.11.0 version of libssh has the ability to
 * add algorithms to the default supported list by prepending
 * "+" to the configuration list. For older versions, we have
 * to specify all the algorithms we want, but as long as at
 * least one succeeds the command won't fail. (That means that
 * it's possible that we won't actually add support for SHA-1,
 * say if it's running on a system in FIPS mode. We could parse
 * the returned list to check.)
 */
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0,11,0)
#define HOSTKEYS_SHA1 "+ssh-rsa"
#define KEY_EXCHANGE_SHA1 "+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"
#define HMAC_SHA1 "+hmac-sha1-etm@openssh.com,hmac-sha1"
#else
#define HOSTKEYS_SHA1 \
	"ssh-ed25519," \
	"ecdsa-sha2-nistp521," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp256," \
	"sk-ssh-ed25519@openssh.com," \
	"sk-ecdsa-sha2-nistp256@openssh.com," \
	"rsa-sha2-512," \
	"rsa-sha2-256," \
	"ssh-rsa"
#define KEY_EXCHANGE_SHA1 \
	"curve25519-sha256,curve25519-sha256@libssh.org," \
	"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521," \
	"diffie-hellman-group18-sha512,diffie-hellman-group16-sha512," \
	"diffie-hellman-group-exchange-sha256," \
	"diffie-hellman-group14-sha256," \
	"diffie-hellman-group-exchange-sha1," \
	"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define HMAC_SHA1 \
	"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com," \
	"hmac-sha2-256,hmac-sha2-512," \
	"hmac-sha1-etm@openssh.com,hmac-sha1"
#endif

static void extcap_log(int priority, const char *function, const char *buffer, void *userdata _U_)
{
	enum ws_log_level level = LOG_LEVEL_DEBUG;
	switch (priority) {
	case SSH_LOG_TRACE:
		level = LOG_LEVEL_NOISY;
		break;
	case SSH_LOG_DEBUG:
		level = LOG_LEVEL_DEBUG;
		break;
	case SSH_LOG_INFO:
		level = LOG_LEVEL_INFO;
		break;
	case SSH_LOG_WARN:
	default:
	/* Prior to 0.11.0 libssh prints far too much at SSH_LOG_WARN,
	 * including merely informational messages.
	 * Lower them to LOG_LEVEL_INFO, which won't get shown in the GUI
	 * and aren't shown by default. (Anything INFO and below goes to
	 * stdout due to ws_log_console_writer_set_use_stdout in extcap-base.c)
	 * After the following commit libssh only uses LOG_LEVEL_WARN for
	 * serious issues:
	 * https://gitlab.com/libssh/libssh-mirror/-/commit/657d9143d121dfff74f5a63f734d0096c7f37194
	 */
#if LIBSSH_VERSION_INT < SSH_VERSION_INT(0,11,0)
		level = LOG_LEVEL_INFO;
#else
		level = LOG_LEVEL_WARNING;
#endif
		break;
	}
	/* We set the libssh log level to specifically ask for this, so don't
	 * both checking the log level a second time.
	 */
	ws_log_write_always_full("libssh", level, NULL, 0, function, "%s", buffer);
}

void add_libssh_info(extcap_parameters * extcap_conf)
{
	extcap_base_set_compiled_with(extcap_conf, "libssh version %s", SSH_STRINGIFY(LIBSSH_VERSION));
	extcap_base_set_running_with(extcap_conf, "libssh version %s", ssh_version(0));
}

ssh_session create_ssh_connection(const ssh_params_t* ssh_params, char** err_info)
{
	ssh_session sshs;
	char* username = NULL;
	unsigned port;

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
		*err_info = ws_strdup_printf("Can't set the host: %s", ssh_params->host);
		goto failure;
	}

	/* Load the configurations already present in the system configuration file. */
	/* They will be overwritten by the user-provided configurations. */
	if (ssh_options_parse_config(sshs, NULL) != 0) {
		*err_info = g_strdup("Unable to load the configuration file");
		goto failure;
	}

	ssh_options_set(sshs, SSH_OPTIONS_LOG_VERBOSITY, &ssh_params->debug);
	ssh_set_log_callback(extcap_log);

	if (ssh_params->ssh_sha1) {
		if (ssh_options_set(sshs, SSH_OPTIONS_HOSTKEYS, HOSTKEYS_SHA1)) {
			*err_info = ws_strdup_printf("Can't set host keys to allow SHA-1.");
			goto failure;
		}
		if (ssh_options_set(sshs, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, HOSTKEYS_SHA1)) {
			*err_info = ws_strdup_printf("Can't set public key algorithms to allow SSH-RSA (SHA-1).");
			goto failure;
		}
		if (ssh_options_set(sshs, SSH_OPTIONS_KEY_EXCHANGE, KEY_EXCHANGE_SHA1)) {
			*err_info = ws_strdup_printf("Can't set key exchange methods to allow SHA-1.");
			goto failure;
		}
		if (ssh_options_set(sshs, SSH_OPTIONS_HMAC_C_S, HMAC_SHA1)) {
			*err_info = ws_strdup_printf("Can't set MAC client to server algorithms to allow SHA-1.");
			goto failure;
		}
		if (ssh_options_set(sshs, SSH_OPTIONS_HMAC_S_C, HMAC_SHA1)) {
			*err_info = ws_strdup_printf("Can't set MAC server to client algorithms to allow SHA-1.");
			goto failure;
		}
	}

	if (ssh_params->port != 0) {
		port = ssh_params->port;
		if (ssh_options_set(sshs, SSH_OPTIONS_PORT, &port)) {
			*err_info = ws_strdup_printf("Can't set the port: %u", port);
			goto failure;
		}
	}

	if (ssh_params->proxycommand) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PROXYCOMMAND, ssh_params->proxycommand)) {
			*err_info = ws_strdup_printf("Can't set the ProxyCommand: %s", ssh_params->proxycommand);
			goto failure;
		}
	}

	if (ssh_params->username) {
		if (ssh_options_set(sshs, SSH_OPTIONS_USER, ssh_params->username)) {
			*err_info = ws_strdup_printf("Can't set the username: %s", ssh_params->username);
			goto failure;
		}
	}

	ssh_options_get(sshs, SSH_OPTIONS_USER, &username);
	ssh_options_get_port(sshs, &port);

	ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Opening ssh connection to %s@%s:%u", username,
		ssh_params->host, port);

	ssh_string_free_char(username);

	/* Connect to server */
	if (ssh_connect(sshs) != SSH_OK) {
		*err_info = ws_strdup_printf("Connection error: %s", ssh_get_error(sshs));
		goto failure;
	}

	/* If a public key path has been provided, try to authenticate using it */
	if (ssh_params->sshkey_path) {
		ssh_key pkey = ssh_key_new();
		int ret;

		ws_info("Connecting using public key in %s...", ssh_params->sshkey_path);
		ret = ssh_pki_import_privkey_file(ssh_params->sshkey_path, ssh_params->sshkey_passphrase, NULL, NULL, &pkey);

		switch (ret) {

		case SSH_OK:
			if (ssh_userauth_publickey(sshs, NULL, pkey) == SSH_AUTH_SUCCESS) {
				ws_info("done");
				ssh_key_free(pkey);
				return sshs;
			}
			ws_info("failed (%s)", ssh_get_error(sshs));
			break;
		case SSH_EOF:
			ws_warning("Error importing key from %s. File doesn't exist or permission denied.",
				ssh_params->sshkey_path);
			break;
		case SSH_ERROR:
			/* Unfortunately we can't call ssh_get_error() on the
			 * key to determine why import failed.
			 */
			ws_warning("Error importing key from %s. Make sure it is a valid"
				" private key file and any necessary passphrase is configured.",
				ssh_params->sshkey_path);
			break;
		default:
			ws_warning("Unknown error from ssh_pki_import_privkey_file");
		}
		ssh_key_free(pkey);
	}

	/* Workaround: it may happen that libssh closes socket in meantime and any next ssh_ call fails so we should detect it in advance */
	if (ssh_get_fd(sshs) != (socket_t)-1) {
		/* If a password has been provided and all previous attempts failed, try to use it */
		if (ssh_params->password) {
			ws_info("Connecting using password...");
			if (ssh_userauth_password(sshs, ssh_params->username, ssh_params->password) == SSH_AUTH_SUCCESS) {
				ws_info("done");
				return sshs;
			}
			ws_info("failed");
		}
	} else {
		ws_info("ssh connection closed before password authentication");
	}

	/* Workaround: it may happen that libssh closes socket in meantime and any next ssh_ call fails so we should detect it in advance */
	if (ssh_get_fd(sshs) != (socket_t)-1) {
		/* Try to authenticate using standard public key */
		ws_info("Connecting using standard public key...");
		if (ssh_userauth_publickey_auto(sshs, NULL, NULL) == SSH_AUTH_SUCCESS) {
			ws_info("done");
			return sshs;
		}
		ws_info("failed");
	} else {
		ws_info("ssh connection closed before public key authentication");
	}

	*err_info = ws_strdup_printf("Can't find a valid authentication. Disconnecting.");

	/* All authentication failed. Disconnect and return */
	ssh_disconnect(sshs);

failure:
	ssh_free(sshs);
	return NULL;
}

int ssh_channel_printf(ssh_channel channel, const char* fmt, ...)
{
	char* buf;
	va_list arg;
	int ret = EXIT_SUCCESS;

	va_start(arg, fmt);
	buf = ws_strdup_vprintf(fmt, arg);
	ws_debug("%s", buf);
	if (ssh_channel_write(channel, buf, (uint32_t)strlen(buf)) == SSH_ERROR)
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

void ssh_params_set_log_level(ssh_params_t* ssh_params, enum ws_log_level level)
{
	switch (level) {
	case LOG_LEVEL_NOISY:
		ssh_params->debug = SSH_LOG_TRACE;
		break;
	case LOG_LEVEL_DEBUG:
		ssh_params->debug = SSH_LOG_DEBUG;
		break;
	case LOG_LEVEL_INFO:
		ssh_params->debug = SSH_LOG_INFO;
		break;
	default:
		ssh_params->debug = SSH_LOG_WARN;
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
