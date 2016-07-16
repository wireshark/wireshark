/* ciscodump.c
 * ciscodump is extcap tool used to capture data using a ssh on a remote cisco router
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
#include <wsutil/interface.h>
#include <extcap/ssh-base.h>
#include <writecap/pcapio.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define CISCODUMP_VERSION_MAJOR "1"
#define CISCODUMP_VERSION_MINOR "0"
#define CISCODUMP_VERSION_RELEASE "0"

/* The read timeout in msec */
#define CISCODUMP_READ_TIMEOUT 3000

#define CISCODUMP_EXTCAP_INTERFACE "cisco"
#define SSH_READ_BLOCK_SIZE 1024
#define SSH_READ_TIMEOUT 10000

#define WIRESHARK_CAPTURE_POINT "WIRESHARK_CAPTURE_POINT"
#define WIRESHARK_CAPTURE_BUFFER "WIRESHARK_CAPTURE_BUFFER"
#define WIRESHARK_CAPTURE_ACCESSLIST "WIRESHARK_CAPTURE_ACCESSLIST"

#define PCAP_SNAPLEN 0xffff

#define PACKET_MAX_SIZE 65535

#define MINIMUM_IOS_MAJOR 12
#define MINIMUM_IOS_MINOR 4

/* Status of the parser */
enum {
	CISCODUMP_PARSER_STARTING,
	CISCODUMP_PARSER_IN_PACKET,
	CISCODUMP_PARSER_IN_HEADER,
	CISCODUMP_PARSER_END_PACKET,
	CISCODUMP_PARSER_ERROR
};

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }

static gboolean verbose = TRUE;

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
	SSH_BASE_OPTIONS,
	{ 0, 0, 0, 0}
};

static char* interfaces_list_to_filter(GSList* interfaces, unsigned int remote_port)
{
	GString* filter = g_string_new(NULL);
	GSList* cur;

	if (interfaces) {
		g_string_append_printf(filter, "deny tcp host %s any eq %u, deny tcp any eq %u host %s",
				(char*)interfaces->data, remote_port, remote_port, (char*)interfaces->data);
		cur = g_slist_next(interfaces);
		while (cur) {
			g_string_append_printf(filter, ", deny tcp host %s any eq %u, deny tcp any eq %u host %s",
				(char*)cur->data, remote_port, remote_port, (char*)cur->data);
			cur = g_slist_next(cur);
		}
		g_string_append_printf(filter, ", permit ip any any");
	}

	return g_string_free(filter, FALSE);
}

static char* local_interfaces_to_filter(const unsigned int remote_port)
{
	GSList* interfaces = local_interfaces_to_list();
	char* filter = interfaces_list_to_filter(interfaces, remote_port);
	g_slist_free_full(interfaces, g_free);
	return filter;
}

/* Read bytes from the channel. If bytes == -1, read all data (until timeout). If outbuf != NULL, data are stored there */
static int read_output_bytes(ssh_channel channel, int bytes, char* outbuf)
{
	char chr;
	int total;
	int bytes_read;

	total = (bytes > 0 ? bytes : G_MAXINT);
	bytes_read = 0;

	while(ssh_channel_read_timeout(channel, &chr, 1, 0, 2000) > 0 && bytes_read < total) {
		verbose_print("%c", chr);
		if (chr == '^')
			return EXIT_FAILURE;
		if (outbuf)
			outbuf[bytes_read] = chr;
		bytes_read++;
	}
	return EXIT_SUCCESS;
}

static void ciscodump_cleanup(ssh_session sshs, ssh_channel channel, const char* iface, const char* cfilter)
{
	if (channel) {
		if (read_output_bytes(channel, -1, NULL) == EXIT_SUCCESS) {
			ssh_channel_printf(channel, "monitor capture point stop %s\n", WIRESHARK_CAPTURE_POINT);
			ssh_channel_printf(channel, "no monitor capture point ip cef %s %s\n", WIRESHARK_CAPTURE_POINT, iface);
			ssh_channel_printf(channel, "no monitor capture buffer %s\n", WIRESHARK_CAPTURE_BUFFER);
			if (cfilter) {
				ssh_channel_printf(channel, "configure terminal\n");
				ssh_channel_printf(channel, "no ip access-list ex %s\n", WIRESHARK_CAPTURE_ACCESSLIST);
			}
			read_output_bytes(channel, -1, NULL);
		}
	}
	ssh_cleanup(&sshs, &channel);
}

static int wait_until_data(ssh_channel channel, const long unsigned count)
{
	long unsigned got = 0;
	char output[SSH_READ_BLOCK_SIZE];
	char* output_ptr;
	guint rounds = 100;

	while (got < count && rounds--) {
		if (ssh_channel_printf(channel, "show monitor capture buffer %s parameters\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE) {
			errmsg_print("Can't write to channel");
			return EXIT_FAILURE;
		}
		if (read_output_bytes(channel, SSH_READ_BLOCK_SIZE, output) == EXIT_FAILURE)
			return EXIT_FAILURE;

		output_ptr = g_strstr_len(output, strlen(output), "Packets");
		if (!output_ptr) {
			errmsg_print("Error in sscanf()");
			return EXIT_FAILURE;
		} else {
			if (sscanf(output_ptr, "Packets : %lu", &got) != 1)
				return EXIT_FAILURE;
		}
	}
	verbose_print("All packets got: dumping\n");
	return EXIT_SUCCESS;
}

static int parse_line(char* packet _U_, unsigned* offset, char* line, int status)
{
	char** parts;
	char** part;
	guint32 value;
	size_t size;

	if (strlen(line) <= 1) {
		if (status == CISCODUMP_PARSER_IN_PACKET)
			return CISCODUMP_PARSER_END_PACKET;
		else
			return status;
	}

	/* we got the packet header                                    */
	/* The packet header is a line like:                           */
	/* 16:09:37.171 ITA Mar 18 2016 : IPv4 LES CEF    : Gi0/1 None */
	if (g_regex_match_simple("^\\d{2}:\\d{2}:\\d{2}.\\d+ .*", line, G_REGEX_CASELESS, G_REGEX_MATCH_ANCHORED)) {
		return CISCODUMP_PARSER_IN_HEADER;
	}

	/* we got a line of the packet                                                          */
	/* A line looks like                                                                    */
	/* <address>: <1st group> <2nd group> <3rd group> <4th group> <ascii representation>    */
	/* ABCDEF01: 01020304 05060708 090A0B0C 0D0E0F10 ................                       */
	/* Note that any of the 4 groups are optional and that a group can be 1 to 4 bytes long */
	parts = g_regex_split_simple(
		"^[\\dA-Z]{8,8}:\\s+([\\dA-Z]{2,8})\\s+([\\dA-Z]{2,8}){0,1}\\s+([\\dA-Z]{2,8}){0,1}\\s+([\\dA-Z]{2,8}){0,1}.*",
		line, G_REGEX_CASELESS, G_REGEX_MATCH_ANCHORED);

	part = parts;
	while(*part) {
		if (strlen(*part) > 1) {
			value = (guint32)strtoul(*part, NULL, 16);
			value = ntohl(value);
			size = strlen(*part) / 2;
			memcpy(packet + *offset, &value, size);
			*offset += (guint32)size;
		}
		part++;
	}
	return CISCODUMP_PARSER_IN_PACKET;
}

static void ssh_loop_read(ssh_channel channel, FILE* fp, const long unsigned count)
{
	char line[SSH_READ_BLOCK_SIZE];
	char chr;
	unsigned offset = 0;
	unsigned packet_size = 0;
	char* packet;
	time_t curtime = time(NULL);
	int err;
	guint64 bytes_written;
	long unsigned packets = 0;
	int status = CISCODUMP_PARSER_STARTING;

	/* This is big enough to put on the heap */
	packet = (char*)g_malloc(PACKET_MAX_SIZE);

	do {
		if (ssh_channel_read_timeout(channel, &chr, 1, FALSE, SSH_READ_TIMEOUT) == SSH_ERROR) {
			errmsg_print("Error reading from channel");
			g_free(packet);
			return;
		}

		if (chr != '\n') {
			line[offset] = chr;
			offset++;
		} else {
			/* Parse the current line */
			line[offset] = '\0';
			status = parse_line(packet, &packet_size, line, status);

			if (status == CISCODUMP_PARSER_END_PACKET) {
				/* dump the packet to the pcap file */
				libpcap_write_packet(fp, curtime, (guint32)(curtime / 1000), packet_size, packet_size, packet, &bytes_written, &err);
				verbose_print("Dumped packet %lu size: %u\n", packets, packet_size);
				packet_size = 0;
				status = CISCODUMP_PARSER_STARTING;
				packets++;
			}
			offset = 0;
		}

	} while(packets < count);

	g_free(packet);
}

static int check_ios_version(ssh_channel channel)
{
	gchar* cmdline = "show version | include Cisco IOS\n";
	gchar version[255];
	guint major = 0;
	guint minor = 0;
	gchar* cur;

	memset(version, 0x0, 255);

	if (ssh_channel_write(channel, cmdline, (guint32)strlen(cmdline)) == SSH_ERROR)
		return FALSE;
	if (read_output_bytes(channel, (int)strlen(cmdline), NULL) == EXIT_FAILURE)
		return FALSE;
	if (read_output_bytes(channel, 255, version) == EXIT_FAILURE)
		return FALSE;

	cur = g_strstr_len(version, strlen(version), "Version");
	if (cur) {
		cur += strlen("Version ");
		if (sscanf(cur, "%u.%u", &major, &minor) != 2)
			return FALSE;

		if ((major > MINIMUM_IOS_MAJOR) || (major == MINIMUM_IOS_MAJOR && minor >= MINIMUM_IOS_MINOR)) {
			verbose_print("Current IOS Version: %u.%u\n", major, minor);
			if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
				return FALSE;
			return TRUE;
		}
	}

	errmsg_print("Invalid IOS version. Minimum version: 12.4, current: %u.%u", major, minor);
	return FALSE;
}

static ssh_channel run_capture(ssh_session sshs, const char* iface, const char* cfilter, const unsigned long int count)
{
	char* cmdline = NULL;
	ssh_channel channel;
	int ret = 0;

	channel = ssh_channel_new(sshs);
	if (!channel)
		return NULL;

	if (ssh_channel_open_session(channel) != SSH_OK)
		goto error;

	if (ssh_channel_request_pty(channel) != SSH_OK)
		goto error;

	if (ssh_channel_change_pty_size(channel, 80, 24) != SSH_OK)
		goto error;

	if (ssh_channel_request_shell(channel) != SSH_OK)
		goto error;

	if (!check_ios_version(channel))
		goto error;

	if (ssh_channel_printf(channel, "terminal length 0\n") == EXIT_FAILURE)
		goto error;

	if (ssh_channel_printf(channel, "monitor capture buffer %s max-size 9500\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE)
		goto error;

	if (ssh_channel_printf(channel, "monitor capture buffer %s limit packet-count %lu\n", WIRESHARK_CAPTURE_BUFFER, count) == EXIT_FAILURE)
		goto error;

	if (cfilter) {
		gchar* multiline_filter;
		gchar* chr;

		if (ssh_channel_printf(channel, "configure terminal\n") == EXIT_FAILURE)
			goto error;

		if (ssh_channel_printf(channel, "ip access-list ex %s\n", WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;

		multiline_filter = g_strdup(cfilter);
		chr = multiline_filter;
		while((chr = g_strstr_len(chr, strlen(chr), ",")) != NULL) {
			chr[0] = '\n';
			verbose_print("Splitting filter into multiline\n");
		}
		ret = ssh_channel_write(channel, multiline_filter, (uint32_t)strlen(multiline_filter));
		g_free(multiline_filter);
		if (ret == SSH_ERROR)
			goto error;

		if (ssh_channel_printf(channel, "\nend\n") == EXIT_FAILURE)
			goto error;

		if (ssh_channel_printf(channel, "monitor capture buffer %s filter access-list %s\n",
				WIRESHARK_CAPTURE_BUFFER, WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;
	}

	if (ssh_channel_printf(channel, "monitor capture point ip cef %s %s both\n", WIRESHARK_CAPTURE_POINT,
			iface) == EXIT_FAILURE)
		goto error;

	if (ssh_channel_printf(channel, "monitor capture point associate %s %s \n", WIRESHARK_CAPTURE_POINT,
			WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE)
		goto error;

	if (ssh_channel_printf(channel, "monitor capture point start %s\n", WIRESHARK_CAPTURE_POINT) == EXIT_FAILURE)
		goto error;

	if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
		goto error;

	if (wait_until_data(channel, count) == EXIT_FAILURE)
		goto error;

	if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
		goto error;

	cmdline = g_strdup_printf("show monitor capture buffer %s dump\n", WIRESHARK_CAPTURE_BUFFER);
	if (ssh_channel_printf(channel, cmdline) == EXIT_FAILURE)
		goto error;

	if (read_output_bytes(channel, (int)strlen(cmdline), NULL) == EXIT_FAILURE)
		goto error;

	g_free(cmdline);
	return channel;
error:
	g_free(cmdline);
	errmsg_print("Error running ssh remote command");
	read_output_bytes(channel, -1, NULL);

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return NULL;
}

static int ssh_open_remote_connection(const char* hostname, const unsigned int port, const char* username, const char* password,
	const char* sshkey, const char* sshkey_passphrase, const char* iface, const char* cfilter,
	const unsigned long int count, const char* fifo)
{
	ssh_session sshs;
	ssh_channel channel;
	FILE* fp = stdout;
	guint64 bytes_written = 0;
	int err;
	int ret = EXIT_FAILURE;
	char* err_info = NULL;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fp = fopen(fifo, "w");
		if (!fp) {
			errmsg_print("Error creating output file: %s\n", g_strerror(errno));
			return EXIT_FAILURE;
		}
	}

	sshs = create_ssh_connection(hostname, port, username, password, sshkey, sshkey_passphrase, &err_info);
	if (!sshs) {
		errmsg_print("Error creating connection: %s", err_info);
		goto cleanup;
	}

	if (!libpcap_write_file_header(fp, 1, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
		errmsg_print("Can't write pcap file header");
		goto cleanup;
	}

	channel = run_capture(sshs, iface, cfilter, count);
	if (!channel) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	verbose_print("\n");

	/* read from channel and write into fp */
	ssh_loop_read(channel, fp, count);

	/* clean up and exit */
	ciscodump_cleanup(sshs, channel, iface, cfilter);

	ret = EXIT_SUCCESS;
cleanup:
	if (fp != stdout)
		fclose(fp);
	verbose_print("\n\n");
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
		"--remote-username myuser --remote-interface gigabit0/0 "
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
	printf("  --remote-interface <iface>: the remote capture interface\n");
	printf("  --remote-filter <filter>: a filter for remote capture (default: don't capture data for local interfaces IPs)\n");
}

static int list_config(char *interface, unsigned int remote_port)
{
	unsigned inc = 0;
	char* ipfilter;

	if (!interface) {
		g_fprintf(stderr, "ERROR: No interface specified.\n");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, CISCODUMP_EXTCAP_INTERFACE)) {
		errmsg_print("ERROR: interface must be %s\n", CISCODUMP_EXTCAP_INTERFACE);
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
	printf("arg {number=%u}{call--sshkey-passphrase}{display=SSH key passphrase}"
		"{type=password}{tooltip=Passphrase to unlock the SSH private key}\n",
		inc++);
	printf("arg {number=%u}{call=--remote-interface}{display=Remote interface}"
		"{type=string}{required=true}{tooltip=The remote network interface used for capture"
		"}\n", inc++);
	printf("arg {number=%u}{call=--remote-filter}{display=Remote capture filter}"
		"{type=string}{tooltip=The remote capture filter}", inc++);
	if (ipfilter)
		printf("{default=%s}", ipfilter);
	printf("\n");
	printf("arg {number=%u}{call=--remote-count}{display=Packets to capture}"
		"{type=unsigned}{required=true}{tooltip=The number of remote packets to capture.}\n",
		inc++);

	g_free(ipfilter);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	int result;
	int option_idx = 0;
	int i;
	char* remote_host = NULL;
	unsigned int remote_port = 22;
	char* remote_username = NULL;
	char* remote_password = NULL;
	char* remote_interface = NULL;
	char* sshkey = NULL;
	char* sshkey_passphrase = NULL;
	char* remote_filter = NULL;
	unsigned long int count = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters * extcap_conf = g_new0(extcap_parameters, 1);

#ifdef _WIN32
	WSADATA wsaData;

	attach_parent_console();
#endif  /* _WIN32 */

	extcap_base_set_util_info(extcap_conf, CISCODUMP_VERSION_MAJOR, CISCODUMP_VERSION_MINOR, CISCODUMP_VERSION_RELEASE, NULL);
	extcap_base_register_interface(extcap_conf, CISCODUMP_EXTCAP_INTERFACE, "Cisco remote capture", 147, "Remote capture dependent DLT");

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		help(argv[0]);
		goto end;
	}

	for (i = 0; i < argc; i++) {
		verbose_print("%s ", argv[i]);
	}
	verbose_print("\n");

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {

		switch (result) {

		case OPT_HELP:
			help(argv[0]);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERBOSE:
			verbose = TRUE;
			break;

		case OPT_VERSION:
			printf("%s.%s.%s\n", CISCODUMP_VERSION_MAJOR, CISCODUMP_VERSION_MINOR, CISCODUMP_VERSION_RELEASE);
			goto end;

		case OPT_REMOTE_HOST:
			g_free(remote_host);
			remote_host = g_strdup(optarg);
			break;

		case OPT_REMOTE_PORT:
			remote_port = (unsigned int)strtoul(optarg, NULL, 10);
			if (remote_port > 65535 || remote_port == 0) {
				printf("Invalid port: %s\n", optarg);
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

		case OPT_REMOTE_FILTER:
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
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg)) {
				errmsg_print("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	if (optind != argc) {
		errmsg_print("Unexpected extra option: %s", argv[optind]);
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
		if (verbose)
			errmsg_print("ERROR: WSAStartup failed with error: %d", result);
		goto end;
	}
#endif  /* _WIN32 */

	if (extcap_conf->capture) {
		if (!remote_host) {
			errmsg_print("Missing parameter: --remote-host");
			goto end;
		}

		if (!remote_interface) {
			errmsg_print("ERROR: No interface specified (--remote-interface)");
			goto end;
		}
		if (count == 0) {
			errmsg_print("ERROR: count of packets must be specified (--remote-count)");
			goto end;
		}

		ret = ssh_open_remote_connection(remote_host, remote_port, remote_username,
			remote_password, sshkey, sshkey_passphrase, remote_interface,
			remote_filter, count, extcap_conf->fifo);
	} else {
		verbose_print("You should not come here... maybe some parameter missing?\n");
		ret = EXIT_FAILURE;
	}

end:
	g_free(remote_host);
	g_free(remote_username);
	g_free(remote_password);
	g_free(remote_interface);
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
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
