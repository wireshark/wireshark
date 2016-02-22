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

#include "extcap-base.h"

#include <glib/gstdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libssh/libssh.h>

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#include "log.h"

#if defined(__FreeBSD__) || defined(BSD) || defined(__APPLE__) || defined(__linux__)
#define USE_GETIFADDRS 1
#include <ifaddrs.h>
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define SSHDUMP_VERSION_MAJOR 1U
#define SSHDUMP_VERSION_MINOR 0U
#define SSHDUMP_VERSION_RELEASE 0U

#define SSH_EXTCAP_INTERFACE "ssh"
#define SSH_READ_BLOCK_SIZE 256

#define DEFAULT_CAPTURE_BIN "dumpcap"

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }

static gboolean verbose = FALSE;

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_REMOTE_HOST,
	OPT_REMOTE_PORT,
	OPT_REMOTE_USERNAME,
	OPT_REMOTE_PASSWORD,
	OPT_REMOTE_INTERFACE,
	OPT_REMOTE_CAPTURE_BIN,
	OPT_REMOTE_FILTER,
	OPT_SSHKEY,
	OPT_SSHKEY_PASSPHRASE,
	OPT_REMOTE_COUNT
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	{ "verbose", optional_argument, NULL, OPT_VERBOSE},
	{ "remote-host", required_argument, NULL, OPT_REMOTE_HOST},
	{ "remote-port", required_argument, NULL, OPT_REMOTE_PORT},
	{ "remote-username", required_argument, NULL, OPT_REMOTE_USERNAME},
	{ "remote-password", required_argument, NULL, OPT_REMOTE_PASSWORD},
	{ "remote-interface", required_argument, NULL, OPT_REMOTE_INTERFACE},
	{ "remote-capture-bin", required_argument, NULL, OPT_REMOTE_CAPTURE_BIN},
	{ "remote-filter", required_argument, NULL, OPT_REMOTE_FILTER},
	{ "remote-count", required_argument, NULL, OPT_REMOTE_COUNT},
	{ "sshkey", required_argument, NULL, OPT_SSHKEY},
	{ "sshkey-passphrase", required_argument, NULL, OPT_SSHKEY_PASSPHRASE},
	{ 0, 0, 0, 0}
};

static char* local_interfaces_to_filter(unsigned int remote_port);

static void ssh_cleanup(ssh_session sshs, ssh_channel channel)
{
	if (channel) {
		ssh_channel_send_eof(channel);
		ssh_channel_close(channel);
		ssh_channel_free(channel);
	}

	if (sshs) {
		ssh_disconnect(sshs);
		ssh_free(sshs);
	}
}

static ssh_session create_ssh_connection(const char* hostname, const unsigned int port, const char* username,
	const char* password, const char* sshkey_path, const char* sshkey_passphrase)
{
	ssh_session sshs;

	/* Open session and set options */
	sshs = ssh_new();
	if (sshs == NULL) {
		errmsg_print("Can't create ssh session");
		return NULL;
	}

	if (!hostname)
		return NULL;

	if (ssh_options_set(sshs, SSH_OPTIONS_HOST, hostname)) {
		errmsg_print("Can't set the hostname: %s", hostname);
		goto failure;
	}

	if (port != 0) {
		if (ssh_options_set(sshs, SSH_OPTIONS_PORT, &port)) {
			errmsg_print("Can't set the port: %d", port);
			goto failure;
		}
	}

	if (!username)
		username = g_get_user_name();

	if (ssh_options_set(sshs, SSH_OPTIONS_USER, username)) {
		errmsg_print("Can't set the username: %s", username);
		goto failure;
	}

	verbose_print("Opening ssh connection to %s@%s:%u", username, hostname, port);

	/* Connect to server */
	if (ssh_connect(sshs) != SSH_OK) {
		errmsg_print("Error connecting to %s@%s:%u (%s)", username, hostname, port,
			ssh_get_error(sshs));
		goto failure;
	}

#ifdef HAVE_LIBSSH_USERAUTH_AGENT
	verbose_print("Connecting using ssh-agent...");
	/* Try to authenticate using ssh agent */
	if (ssh_userauth_agent(sshs, NULL) == SSH_AUTH_SUCCESS) {
		verbose_print("done\n");
		return sshs;
	}
	verbose_print("failed\n");
#endif

	/* If a public key path has been provided, try to authenticate using it */
	if (sshkey_path) {
		ssh_key pkey = ssh_key_new();
		int ret;

		verbose_print("Connecting using public key in %s...", sshkey_path);
		ret = ssh_pki_import_privkey_file(sshkey_path, sshkey_passphrase, NULL, NULL, &pkey);

		if (ret == SSH_OK) {
			if (ssh_userauth_publickey(sshs, NULL, pkey) == SSH_AUTH_SUCCESS) {
				verbose_print("done\n");
				ssh_key_free(pkey);
				return sshs;
			}
		}
		ssh_key_free(pkey);
		verbose_print("failed (%s)\n", ssh_get_error(sshs));
	}

	/* Try to authenticate using standard public key */
	verbose_print("Connecting using standard public key...");
	if (ssh_userauth_publickey_auto(sshs, NULL, NULL) == SSH_AUTH_SUCCESS) {
		verbose_print("done\n");
		return sshs;
	}
	verbose_print("failed\n");

	/* If a password has been provided and all previous attempts failed, try to use it */
	if (password) {
		verbose_print("Connecting using password...");
		if (ssh_userauth_password(sshs, username, password) == SSH_AUTH_SUCCESS) {
			verbose_print("done\n");
			return sshs;
		}
		verbose_print("failed\n");
	}

	errmsg_print("Can't find a valid authentication. Disconnecting.");

	/* All authentication failed. Disconnect and return */
	ssh_disconnect(sshs);

failure:
	ssh_free(sshs);
	return NULL;
}

static void ssh_loop_read(ssh_channel channel, int fd)
{
	int nbytes;
	char buffer[SSH_READ_BLOCK_SIZE];

	/* read from stdin until data are available */
	do {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 0);
		if (write(fd, buffer, nbytes) != nbytes) {
			errmsg_print("ERROR reading: %s", g_strerror(errno));
			return;
		}
	} while(nbytes > 0);

	/* read loop finished... maybe something wrong happened. Read from stderr */
	do {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 1);
		if (write(STDERR_FILENO, buffer, nbytes) != nbytes) {
			return;
		}
	} while(nbytes > 0);

	if (ssh_channel_send_eof(channel) != SSH_OK)
		return;
}

static ssh_channel run_ssh_command(ssh_session sshs, const char* capture_bin, const char* iface, const char* cfilter,
		unsigned long int count)
{
	gchar* cmdline;
	ssh_channel channel;
	char* quoted_bin;
	char* quoted_iface;
	char* default_filter;
	char* quoted_filter;
	char* count_str = NULL;
	unsigned int remote_port = 22;

	if (!capture_bin)
		capture_bin = DEFAULT_CAPTURE_BIN;

	if (!iface)
		iface = "eth0";

	channel = ssh_channel_new(sshs);
	if (!channel)
		return NULL;

	if (ssh_channel_open_session(channel) != SSH_OK) {
		ssh_channel_free(channel);
		return NULL;
	}

	ssh_options_get_port(sshs, &remote_port);

	/* escape parameters to go save with the shell */
	quoted_bin = g_shell_quote(capture_bin);
	quoted_iface = g_shell_quote(iface);
	default_filter = local_interfaces_to_filter(remote_port);
	if (!cfilter)
		cfilter = default_filter;
	quoted_filter = g_shell_quote(cfilter);
	if (count > 0)
		count_str = g_strdup_printf("-c %lu", count);

	cmdline = g_strdup_printf("%s -i %s -P -w - -f %s %s", quoted_bin, quoted_iface, quoted_filter,
		count_str ? count_str : "");

	verbose_print("Running: %s\n", cmdline);
	if (ssh_channel_request_exec(channel, cmdline) != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		channel = NULL;
	}

	g_free(quoted_bin);
	g_free(quoted_iface);
	g_free(default_filter);
	g_free(quoted_filter);
	g_free(cmdline);
	if (count_str)
		g_free(count_str);

	return channel;
}

static int ssh_open_remote_connection(const char* hostname, const unsigned int port, const char* username, const char* password,
	const char* sshkey, const char* sshkey_passphrase, const char* iface, const char* cfilter, const char* capture_bin,
	const unsigned long int count, const char* fifo)
{
	ssh_session sshs = NULL;
	ssh_channel channel = NULL;
	int fd = STDOUT_FILENO;
	int ret = EXIT_FAILURE;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fd = open(fifo, O_WRONLY);
		if (fd == -1) {
			fd = open(fifo, O_WRONLY | O_CREAT, 0640);
			if (fd == -1) {
				errmsg_print("Error creating output file: %s", g_strerror(errno));
				return EXIT_FAILURE;
			}
		}
	}

	sshs = create_ssh_connection(hostname, port, username, password, sshkey, sshkey_passphrase);

	if (!sshs)
		goto cleanup;

	channel = run_ssh_command(sshs, capture_bin, iface, cfilter, count);
	if (!channel)
		goto cleanup;

	/* read from channel and write into fd */
	ssh_loop_read(channel, fd);

	ret = EXIT_SUCCESS;
cleanup:
	/* clean up and exit */
	ssh_cleanup(sshs, channel);

	if (g_strcmp0(fifo, "-"))
		close(fd);
	return ret;
}

static void help(const char* binname)
{
	printf("Help\n");
	printf(" Usage:\n");
	printf(" %s --extcap-interfaces\n", binname);
	printf(" %s --extcap-interface=INTERFACE --extcap-dlts\n", binname);
	printf(" %s --extcap-interface=INTERFACE --extcap-config\n", binname);
	printf(" %s --extcap-interface=INTERFACE --remote-host myhost --remote-port 22222 "
		"--remote-username myuser --remote-interface eth2 --remote-capture-bin /bin/dumpcap "
		"--fifo=FILENAME --capture\n", binname);
	printf("\n\n");
	printf("  --help: print this help\n");
	printf("  --version: print the version\n");
	printf("  --verbose: print more messages\n");
	printf("  --extcap-interfaces: list the interfaces\n");
	printf("  --extcap-interface <iface>: specify the interface\n");
	printf("  --extcap-dlts: list the DTLs for an interface\n");
	printf("  --extcap-config: list the additional configuration for an interface\n");
	printf("  --extcap-capture-filter <filter>: the capture filter\n");
	printf("  --capture: run the capture\n");
	printf("  --fifo <file>: dump data to file or fifo\n");
	printf("  --remote-host <host>: the remote SSH host\n");
	printf("  --remote-port <port>: the remote SSH port (default: 22)\n");
	printf("  --remote-username <username>: the remote SSH username (default: the current user)\n");
	printf("  --remote-password <password>: the remote SSH password. If not specified, ssh-agent and ssh-key are used\n");
	printf("  --sshkey <public key path>: the path of the ssh key\n");
	printf("  --sshkey-passphrase <public key passphrase>: the passphrase to unlock public ssh\n");
	printf("  --remote-interface <iface>: the remote capture interface (default: eth0)\n");
	printf("  --remote-capture-bin <capture bin>: the remote dumcap binary (default: %s)\n", DEFAULT_CAPTURE_BIN);
	printf("  --remote-filter <filter>: a filter for remote capture (default: don't listen on local local interfaces IPs)\n");
}

static int list_interfaces(void)
{
	printf("extcap {version=%u.%u.%u}\n", SSHDUMP_VERSION_MAJOR, SSHDUMP_VERSION_MINOR, SSHDUMP_VERSION_RELEASE);
	printf("interface {value=%s}{display=SSH remote capture}\n", SSH_EXTCAP_INTERFACE);
	return EXIT_SUCCESS;
}

static int list_dlts(const char *interface)
{
	if (!interface) {
		errmsg_print("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, SSH_EXTCAP_INTERFACE)) {
		errmsg_print("ERROR: interface must be %s", SSH_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("dlt {number=147}{name=%s}{display=Remote capture dependant DLT}\n", SSH_EXTCAP_INTERFACE);
	return EXIT_SUCCESS;
}


static char* local_interfaces_to_filter(unsigned int remote_port)
{
	char* filter = NULL;
#ifdef USE_GETIFADDRS
	struct ifaddrs* ifap;
	struct ifaddrs* ifa;
	GString* interfaces;
	int family;
	char ip[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifap)) {
		goto end;
	}

	interfaces = g_string_new(NULL);

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		memset(&ip, 0x0, INET6_ADDRSTRLEN);

		switch (family) {
			case AF_INET:
				{
					struct sockaddr_in *addr4 = (struct sockaddr_in *)ifa->ifa_addr;
					inet_ntop(family, (char *)&addr4->sin_addr, ip, sizeof(ip));
					break;
				}

			case AF_INET6:
				{
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					inet_ntop(family, (char *)&addr6->sin6_addr, ip, sizeof(ip));
					break;
				}

			default:
				break;
		}

		/* skip loopback addresses */
		if (!g_strcmp0(ip, "127.0.0.1") || !g_strcmp0(ip, "::1"))
			continue;

		if (*ip) {
			if (interfaces->len)
				g_string_append(interfaces, " or ");
			g_string_append_printf(interfaces, "host %s", ip);
		}
	}
	freeifaddrs(ifap);

	if (interfaces->len)
		filter = g_strdup_printf("not ((%s) and port %u)", interfaces->str, remote_port);

	g_string_free(interfaces, TRUE);
end:
#endif
	if (!filter)
		filter = g_strdup_printf("not port %u", remote_port);
	return filter;
}

static int list_config(char *interface, unsigned int remote_port)
{
	unsigned inc = 0;
	char* ipfilter;

	if (!interface) {
		errmsg_print("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, SSH_EXTCAP_INTERFACE)) {
		errmsg_print("ERROR: interface must be %s", SSH_EXTCAP_INTERFACE);
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
	printf("arg {number=%u}{call=--remote-capture-bin}{display=Remote capture binary}"
		"{type=string}{default=%s}{tooltip=The remote dumpcap binary used "
		"for capture.}\n", inc++, DEFAULT_CAPTURE_BIN);
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
	int do_list_interfaces = 0;
	int do_config = 0;
	int do_capture = 0;
	int i;
	char* interface = NULL;
	char* remote_host = NULL;
	unsigned int remote_port = 22;
	char* remote_username = NULL;
	char* remote_password = NULL;
	int do_dlts = 0;
	char* fifo = NULL;
	char* remote_interface = NULL;
	char* remote_capture_bin = NULL;
	char* extcap_filter = NULL;
	char* sshkey = NULL;
	char* sshkey_passphrase = NULL;
	char* remote_filter = NULL;
	unsigned long int count = 0;

#ifdef _WIN32
	WSADATA wsaData;

	attach_parent_console();
#endif  /* _WIN32 */

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		help(argv[0]);
		return EXIT_FAILURE;
	}

	for (i = 0; i < argc; i++) {
		verbose_print("%s ", argv[i]);
	}
	verbose_print("\n");

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {

		switch (result) {

		case OPT_HELP:
			help(argv[0]);
			return EXIT_SUCCESS;

		case OPT_VERBOSE:
			verbose = TRUE;
			break;

		case OPT_VERSION:
			printf("%u.%u.%u\n", SSHDUMP_VERSION_MAJOR, SSHDUMP_VERSION_MINOR, SSHDUMP_VERSION_RELEASE);
			return EXIT_SUCCESS;

		case OPT_LIST_INTERFACES:
			do_list_interfaces = 1;
			break;

		case OPT_LIST_DLTS:
			do_dlts = 1;
			break;

		case OPT_INTERFACE:
			if (interface)
				g_free(interface);
			interface = g_strdup(optarg);
			break;

		case OPT_CONFIG:
			do_config = 1;
			break;

		case OPT_CAPTURE:
			do_capture = 1;
			break;

		case OPT_FIFO:
			if (fifo)
				g_free(fifo);
			fifo = g_strdup(optarg);
			break;

		case OPT_REMOTE_HOST:
			if (remote_host)
				g_free(remote_host);
			remote_host = g_strdup(optarg);
			break;

		case OPT_REMOTE_PORT:
			remote_port = (unsigned int)strtoul(optarg, NULL, 10);
			if (remote_port > 65535 || remote_port == 0) {
				errmsg_print("Invalid port: %s", optarg);
				return EXIT_FAILURE;
			}
			break;

		case OPT_REMOTE_USERNAME:
			if (remote_username)
				g_free(remote_username);
			remote_username = g_strdup(optarg);
			break;

		case OPT_REMOTE_PASSWORD:
			if (remote_password)
				g_free(remote_password);
			remote_password = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_SSHKEY:
			if (sshkey)
				g_free(sshkey);
			sshkey = g_strdup(optarg);
			break;

		case OPT_SSHKEY_PASSPHRASE:
			if (sshkey_passphrase)
				g_free(sshkey_passphrase);
			sshkey_passphrase = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_REMOTE_INTERFACE:
			if (remote_interface)
				g_free(remote_interface);
			remote_interface = g_strdup(optarg);
			break;

		case OPT_REMOTE_CAPTURE_BIN:
			if (remote_capture_bin)
				g_free(remote_capture_bin);
			remote_capture_bin = g_strdup(optarg);
			break;

		case OPT_CAPTURE_FILTER:
			if (extcap_filter)
				g_free(extcap_filter);
			extcap_filter = g_strdup(optarg);
			break;

		case OPT_REMOTE_FILTER:
			if (remote_filter)
				g_free(remote_filter);
			remote_filter = g_strdup(optarg);
			break;

		case OPT_REMOTE_COUNT:
			count = strtoul(optarg, NULL, 10);
			break;

		case ':':
			/* missing option argument */
			errmsg_print("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			errmsg_print("Invalid option: %s", argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}

	if (optind != argc) {
		errmsg_print("Unexpected extra option: %s", argv[optind]);
		return EXIT_FAILURE;
	}

	if (do_list_interfaces)
		return list_interfaces();

	if (do_config)
		return list_config(interface, remote_port);

	if (do_dlts)
		return list_dlts(interface);

#ifdef _WIN32
	result = WSAStartup(MAKEWORD(1,1), &wsaData);
	if (result != 0) {
		if (verbose)
			errmsg_print("ERROR: WSAStartup failed with error: %d", result);
		return 1;
	}
#endif  /* _WIN32 */

	if (do_capture) {
		char* filter;
		int ret = 0;
		if (!fifo) {
			errmsg_print("ERROR: No FIFO or file specified");
			return 1;
		}
		if (g_strcmp0(interface, SSH_EXTCAP_INTERFACE)) {
			errmsg_print("ERROR: invalid interface");
			return 1;
		}
		if (!remote_host) {
			errmsg_print("Missing parameter: --remote-host");
			return 1;
		}
		filter = concat_filters(extcap_filter, remote_filter);
		ret = ssh_open_remote_connection(remote_host, remote_port, remote_username,
			remote_password, sshkey, sshkey_passphrase, remote_interface,
			filter, remote_capture_bin, count, fifo);
		g_free(filter);
		return ret;
	}

	verbose_print("You should not come here... maybe some parameter missing?\n");
	return 1;
}


#ifdef _WIN32
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
		LPSTR lpCmdLine, int nCmdShow) {
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
