/* sshdump.c
 * sshdump is extcap tool used to capture data using a remote ssh host
 *
 * Copyright 2015, Dario Lombardo
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

#include <extcap/extcap-base.h>
#include <extcap/ssh-base.h>
#include <wsutil/interface.h>
#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/glib-compat.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define SSHDUMP_VERSION_MAJOR "1"
#define SSHDUMP_VERSION_MINOR "0"
#define SSHDUMP_VERSION_RELEASE "0"

#define SSH_EXTCAP_INTERFACE "ssh"
#define SSH_READ_BLOCK_SIZE 256

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_REMOTE_HOST,
	OPT_REMOTE_PORT,
	OPT_REMOTE_USERNAME,
	OPT_REMOTE_PASSWORD,
	OPT_REMOTE_INTERFACE,
	OPT_REMOTE_CAPTURE_COMMAND,
	OPT_REMOTE_FILTER,
	OPT_SSHKEY,
	OPT_SSHKEY_PASSPHRASE,
	OPT_REMOTE_COUNT,
	OPT_REMOTE_SUDO
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	SSH_BASE_OPTIONS,
	{ "remote-capture-command", required_argument, NULL, OPT_REMOTE_CAPTURE_COMMAND},
	{ "remote-sudo", required_argument, NULL, OPT_REMOTE_SUDO },
	{ 0, 0, 0, 0}
};

static char* interfaces_list_to_filter(GSList* if_list, const unsigned int remote_port);

static int ssh_loop_read(ssh_channel channel, FILE* fp)
{
	int nbytes;
	int ret = EXIT_SUCCESS;
	char buffer[SSH_READ_BLOCK_SIZE];

	/* read from stdin until data are available */
	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 0);
		if (nbytes < 0) {
			g_warning("Error reading from channel");
			goto end;
		}
		if (nbytes == 0) {
			goto end;
		}
		if (fwrite(buffer, 1, nbytes, fp) != (guint)nbytes) {
			g_warning("Error writing to fifo");
			ret = EXIT_FAILURE;
			goto end;
		}
		fflush(fp);
	}

	/* read loop finished... maybe something wrong happened. Read from stderr */
	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 1);
		if (nbytes < 0) {
			g_warning("Error reading from channel");
			goto end;
		}
		if (fwrite(buffer, 1, nbytes, stderr) != (guint)nbytes) {
			g_warning("Error writing to stderr");
			break;
		}
	}

end:
	if (ssh_channel_send_eof(channel) != SSH_OK) {
		g_warning("Error sending EOF in ssh channel");
		ret = EXIT_FAILURE;
	}
	return ret;
}

static char* local_interfaces_to_filter(const guint16 remote_port)
{
	GSList* interfaces = local_interfaces_to_list();
	char* filter = interfaces_list_to_filter(interfaces, remote_port);
	g_slist_free_full(interfaces, g_free);
	return filter;
}

static ssh_channel run_ssh_command(ssh_session sshs, const char* capture_command, const gboolean use_sudo, const char* iface,
		const char* cfilter, const guint32 count)
{
	gchar* cmdline;
	ssh_channel channel;
	char* quoted_iface = NULL;
	char* quoted_filter = NULL;
	char* count_str = NULL;
	unsigned int remote_port = 22;

	if (!iface)
		iface = "eth0";

	channel = ssh_channel_new(sshs);
	if (!channel) {
		g_warning("Can't create channel");
		return NULL;
	}

	if (ssh_channel_open_session(channel) != SSH_OK) {
		g_warning("Can't open session");
		ssh_channel_free(channel);
		return NULL;
	}

	ssh_options_get_port(sshs, &remote_port);

	/* escape parameters to go save with the shell */
	if (capture_command && *capture_command) {
		cmdline = g_strdup(capture_command);
		g_debug("Remote capture command has disabled other options");
	} else {
		quoted_iface = g_shell_quote(iface);
		quoted_filter = g_shell_quote(cfilter ? cfilter : "");
		if (count > 0)
			count_str = g_strdup_printf("-c %u", count);

		cmdline = g_strdup_printf("%s tcpdump -U -i %s -w - %s %s", use_sudo ? "sudo" : "", quoted_iface,
			count_str ? count_str : "", quoted_filter);
	}

	g_debug("Running: %s", cmdline);
	if (ssh_channel_request_exec(channel, cmdline) != SSH_OK) {
		g_warning("Can't request exec");
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		channel = NULL;
	}

	g_free(quoted_iface);
	g_free(quoted_filter);
	g_free(cmdline);
	if (count_str)
		g_free(count_str);

	return channel;
}

static int ssh_open_remote_connection(const char* hostname, const unsigned int port, const char* username, const char* password,
	const char* sshkey, const char* sshkey_passphrase, const char* iface, const char* cfilter, const char* capture_command,
	const gboolean use_sudo, const guint32 count, const char* fifo)
{
	ssh_session sshs = NULL;
	ssh_channel channel = NULL;
	FILE* fp = stdout;
	int ret = EXIT_FAILURE;
	char* err_info = NULL;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fp = fopen(fifo, "wb");
		if (fp == NULL) {
			g_warning("Error creating output file: %s (%s)", fifo, g_strerror(errno));
			return EXIT_FAILURE;
		}
	}

	sshs = create_ssh_connection(hostname, port, username, password, sshkey, sshkey_passphrase, &err_info);

	if (!sshs) {
		g_warning("Error creating connection: %s", err_info);
		goto cleanup;
	}

	channel = run_ssh_command(sshs, capture_command, use_sudo, iface, cfilter, count);

	if (!channel) {
		g_warning("Can't run ssh command");
		goto cleanup;
	}

	/* read from channel and write into fp */
	if (ssh_loop_read(channel, fp) != EXIT_SUCCESS) {
		g_warning("Error in read loop");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	ret = EXIT_SUCCESS;
cleanup:
	if (err_info)
		g_warning("%s", err_info);
	g_free(err_info);

	/* clean up and exit */
	ssh_cleanup(&sshs, &channel);

	if (g_strcmp0(fifo, "-"))
		fclose(fp);
	return ret;
}

static char* interfaces_list_to_filter(GSList* interfaces, const unsigned int remote_port)
{
	GString* filter = g_string_new(NULL);
	GSList* cur;

	if (!interfaces) {
		g_string_append_printf(filter, "not port %u", remote_port);
	} else {
		g_string_append_printf(filter, "not ((host %s", (char*)interfaces->data);
		cur = g_slist_next(interfaces);
		while (cur) {
			g_string_append_printf(filter, " or host %s", (char*)cur->data);
			cur = g_slist_next(cur);
		}
		g_string_append_printf(filter, ") and port %u)", remote_port);
	}
	return g_string_free(filter, FALSE);
}

static int list_config(char *interface, unsigned int remote_port)
{
	unsigned inc = 0;
	char* ipfilter;

	if (!interface) {
		g_warning("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, SSH_EXTCAP_INTERFACE)) {
		g_warning("ERROR: interface must be %s", SSH_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	ipfilter = local_interfaces_to_filter(remote_port);

	printf("arg {number=%u}{call=--remote-host}{display=Remote SSH server address}"
		"{type=string}{tooltip=The remote SSH host. It can be both "
		"an IP address or a hostname}{required=true}\n", inc++);
	printf("arg {number=%u}{call=--remote-port}{display=Remote SSH server port}"
		"{type=unsigned}{default=22}{tooltip=The remote SSH host port (1-65535)}"
		"{range=1,65535}\n", inc++);
	printf("arg {number=%u}{call=--remote-username}{display=Remote SSH server username}"
		"{type=string}{default=%s}{tooltip=The remote SSH username. If not provided, "
		"the current user will be used}\n", inc++, g_get_user_name());
	printf("arg {number=%u}{call=--remote-password}{display=Remote SSH server password}"
		"{type=password}{tooltip=The SSH password, used when other methods (SSH agent "
		"or key files) are unavailable.}\n", inc++);
	printf("arg {number=%u}{call=--sshkey}{display=Path to SSH private key}"
		"{type=fileselect}{tooltip=The path on the local filesystem of the private ssh key}\n",
		inc++);
	printf("arg {number=%u}{call=--sshkey-passphrase}{display=SSH key passphrase}"
		"{type=password}{tooltip=Passphrase to unlock the SSH private key}\n",
		inc++);
	printf("arg {number=%u}{call=--remote-interface}{display=Remote interface}"
		"{type=string}{default=eth0}{tooltip=The remote network interface used for capture"
		"}\n", inc++);
	printf("arg {number=%u}{call=--remote-capture-command}{display=Remote capture command}"
		"{type=string}{tooltip=The remote command used to capture}\n", inc++);
	printf("arg {number=%u}{call=--remote-sudo}{display=Use sudo on the remote machine}"
		"{type=boolean}{tooltip=Prepend the capture command with sudo on the remote machine}\n", inc++);
	printf("arg {number=%u}{call=--remote-filter}{display=Remote capture filter}"
		"{type=string}{tooltip=The remote capture filter}", inc++);
	if (ipfilter)
		printf("{default=%s}", ipfilter);
	printf("\n");
	printf("arg {number=%u}{call=--remote-count}{display=Packets to capture}"
		"{type=unsigned}{default=0}{tooltip=The number of remote packets to capture. (Default: inf)}\n",
		inc++);

	g_free(ipfilter);

	return EXIT_SUCCESS;
}

static char* concat_filters(const char* extcap_filter, const char* remote_filter)
{
	if (!extcap_filter && remote_filter)
		return g_strdup(remote_filter);

	if (!remote_filter && extcap_filter)
		return g_strdup(extcap_filter);

	if (!remote_filter && !extcap_filter)
		return NULL;

	return g_strdup_printf("(%s) and (%s)", extcap_filter, remote_filter);
}

int main(int argc, char **argv)
{
	int result;
	int option_idx = 0;
	int i;
	char* remote_host = NULL;
	guint16 remote_port = 22;
	char* remote_username = NULL;
	char* remote_password = NULL;
	char* remote_interface = NULL;
	char* remote_capture_command = NULL;
	char* sshkey = NULL;
	char* sshkey_passphrase = NULL;
	char* remote_filter = NULL;
	guint32 count = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters * extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;
	gboolean use_sudo = FALSE;

#ifdef _WIN32
	WSADATA wsaData;

	attach_parent_console();
#endif  /* _WIN32 */

	help_url = data_file_url("sshdump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], SSHDUMP_VERSION_MAJOR, SSHDUMP_VERSION_MINOR,
		SSHDUMP_VERSION_RELEASE, help_url);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, SSH_EXTCAP_INTERFACE, "SSH remote capture", 147, "Remote capture dependent DLT");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --remote-host myhost --remote-port 22222 "
		"--remote-username myuser --remote-interface eth2 --remote-capture-command 'tcpdump -U -i eth0 -w -' "
		"--fifo=FILENAME --capture\n", argv[0], argv[0], SSH_EXTCAP_INTERFACE, argv[0],
		SSH_EXTCAP_INTERFACE, argv[0], SSH_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--remote-host <host>", "the remote SSH host");
	extcap_help_add_option(extcap_conf, "--remote-port <port>", "the remote SSH port (default: 22)");
	extcap_help_add_option(extcap_conf, "--remote-username <username>", "the remote SSH username (default: the current user)");
	extcap_help_add_option(extcap_conf, "--remote-password <password>", "the remote SSH password. If not specified, ssh-agent and ssh-key are used");
	extcap_help_add_option(extcap_conf, "--sshkey <public key path>", "the path of the ssh key");
	extcap_help_add_option(extcap_conf, "--sshkey-passphrase <public key passphrase>", "the passphrase to unlock public ssh");
	extcap_help_add_option(extcap_conf, "--remote-interface <iface>", "the remote capture interface (default: eth0)");
	extcap_help_add_option(extcap_conf, "--remote-capture-command <capture command>", "the remote capture command");
	extcap_help_add_option(extcap_conf, "--remote-sudo yes", "use sudo on the remote machine to capture");
	extcap_help_add_option(extcap_conf, "--remote-filter <filter>", "a filter for remote capture (default: don't "
		"listen on local interfaces IPs)");
	extcap_help_add_option(extcap_conf, "--remote-count <count>", "the number of packets to capture");

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {

		switch (result) {

		case OPT_HELP:
			extcap_help_print(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERSION:
			printf("%s\n", extcap_conf->version);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_REMOTE_HOST:
			g_free(remote_host);
			remote_host = g_strdup(optarg);
			break;

		case OPT_REMOTE_PORT:
			if (!ws_strtou16(optarg, NULL, &remote_port) || remote_port == 0) {
				g_warning("Invalid port: %s", optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_USERNAME:
			g_free(remote_username);
			remote_username = g_strdup(optarg);
			break;

		case OPT_REMOTE_PASSWORD:
			g_free(remote_password);
			remote_password = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_SSHKEY:
			g_free(sshkey);
			sshkey = g_strdup(optarg);
			break;

		case OPT_SSHKEY_PASSPHRASE:
			g_free(sshkey_passphrase);
			sshkey_passphrase = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_REMOTE_INTERFACE:
			g_free(remote_interface);
			remote_interface = g_strdup(optarg);
			break;

		case OPT_REMOTE_CAPTURE_COMMAND:
			g_free(remote_capture_command);
			remote_capture_command = g_strdup(optarg);
			break;

		case OPT_REMOTE_SUDO:
			use_sudo = TRUE;
			break;

		case OPT_REMOTE_FILTER:
			g_free(remote_filter);
			remote_filter = g_strdup(optarg);
			break;

		case OPT_REMOTE_COUNT:
			if (!ws_strtou32(optarg, NULL, &count)) {
				g_warning("Invalid value for count: %s", optarg);
				goto end;
			}
			break;

		case ':':
			/* missing option argument */
			g_warning("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg)) {
				g_warning("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	for (i = 0; i < argc; i++)
		g_debug("%s", argv[i]);

	if (optind != argc) {
		g_warning("Unexpected extra option: %s", argv[optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface, remote_port);
		goto end;
	}

#ifdef _WIN32
	result = WSAStartup(MAKEWORD(1,1), &wsaData);
	if (result != 0) {
		g_warning("ERROR: WSAStartup failed with error: %d", result);
		goto end;
	}
#endif  /* _WIN32 */

	if (extcap_conf->capture) {
		char* filter;

		if (!remote_host) {
			g_warning("Missing parameter: --remote-host");
			goto end;
		}
		filter = concat_filters(extcap_conf->capture_filter, remote_filter);
		ret = ssh_open_remote_connection(remote_host, remote_port, remote_username,
			remote_password, sshkey, sshkey_passphrase, remote_interface,
			filter, remote_capture_command, use_sudo, count, extcap_conf->fifo);
		g_free(filter);
	} else {
		g_debug("You should not come here... maybe some parameter missing?");
		ret = EXIT_FAILURE;
	}

end:
	/* clean up stuff */
	g_free(remote_host);
	g_free(remote_username);
	g_free(remote_password);
	g_free(remote_interface);
	g_free(remote_capture_command);
	g_free(sshkey);
	g_free(sshkey_passphrase);
	g_free(remote_filter);
	extcap_base_cleanup(&extcap_conf);
	return ret;
}

#ifdef _WIN32
int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
        struct HINSTANCE__ *hPrevInstance,
        char               *lpszCmdLine,
        int                 nCmdShow)
{
	return main(__argc, __argv);
}
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
