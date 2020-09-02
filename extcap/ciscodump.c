/* ciscodump.c
 * ciscodump is extcap tool used to capture data using a ssh on a remote cisco router
 *
 * Copyright 2015, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <extcap/extcap-base.h>
#include <wsutil/interface.h>
#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/please_report_bug.h>
#include <extcap/ssh-base.h>
#include <writecap/pcapio.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <cli_main.h>

#define CISCODUMP_VERSION_MAJOR "1"
#define CISCODUMP_VERSION_MINOR "0"
#define CISCODUMP_VERSION_RELEASE "0"

/* The read timeout in msec */
#define CISCODUMP_READ_TIMEOUT 3000

#define CISCODUMP_EXTCAP_INTERFACE "ciscodump"
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

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_REMOTE_HOST,
	OPT_REMOTE_PORT,
	OPT_REMOTE_USERNAME,
	OPT_REMOTE_PASSWORD,
	OPT_REMOTE_INTERFACE,
	OPT_REMOTE_FILTER,
	OPT_SSHKEY,
	OPT_SSHKEY_PASSPHRASE,
	OPT_PROXYCOMMAND,
	OPT_REMOTE_COUNT
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
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
		g_debug("%c", chr);
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

static int wait_until_data(ssh_channel channel, const guint32 count)
{
	long unsigned got = 0;
	char output[SSH_READ_BLOCK_SIZE];
	char* output_ptr;
	guint rounds = 100;

	while (got < count && rounds--) {
		if (ssh_channel_printf(channel, "show monitor capture buffer %s parameters\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE) {
			g_warning("Can't write to channel");
			return EXIT_FAILURE;
		}
		if (read_output_bytes(channel, SSH_READ_BLOCK_SIZE, output) == EXIT_FAILURE)
			return EXIT_FAILURE;

		output_ptr = g_strstr_len(output, strlen(output), "Packets");
		if (!output_ptr) {
			g_warning("Error in sscanf()");
			return EXIT_FAILURE;
		} else {
			if (sscanf(output_ptr, "Packets : %lu", &got) != 1)
				return EXIT_FAILURE;
		}
	}
	g_debug("All packets got: dumping");
	return EXIT_SUCCESS;
}

static int parse_line(guint8* packet, unsigned* offset, char* line, int status)
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
	if (g_regex_match_simple("^\\d{2}:\\d{2}:\\d{2}.\\d+ .*", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), G_REGEX_MATCH_ANCHORED)) {
		return CISCODUMP_PARSER_IN_HEADER;
	}

	/* we got a line of the packet                                                          */
	/* A line looks like                                                                    */
	/* <address>: <1st group> <2nd group> <3rd group> <4th group> <ascii representation>    */
	/* ABCDEF01: 01020304 05060708 090A0B0C 0D0E0F10 ................                       */
	/* Note that any of the 4 groups are optional and that a group can be 1 to 4 bytes long */
	parts = g_regex_split_simple(
		"^[\\dA-F]{8,8}:\\s+([\\dA-F]{2,8})\\s+([\\dA-F]{2,8}){0,1}\\s+([\\dA-F]{2,8}){0,1}\\s+([\\dA-F]{2,8}){0,1}.*",
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
	g_strfreev(parts);
	return CISCODUMP_PARSER_IN_PACKET;
}

static void ssh_loop_read(ssh_channel channel, FILE* fp, const guint32 count)
{
	char line[SSH_READ_BLOCK_SIZE];
	char chr;
	unsigned offset = 0;
	unsigned packet_size = 0;
	guint8* packet;
	gint64 curtime = g_get_real_time();
	int err;
	guint64 bytes_written;
	long unsigned packets = 0;
	int status = CISCODUMP_PARSER_STARTING;

	/* This is big enough to put on the heap */
	packet = (guint8*)g_malloc(PACKET_MAX_SIZE);

	do {
		if (ssh_channel_read_timeout(channel, &chr, 1, FALSE, SSH_READ_TIMEOUT) == SSH_ERROR) {
			g_warning("Error reading from channel");
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
				if (!libpcap_write_packet(fp,
						(guint32)(curtime / G_USEC_PER_SEC), (guint32)(curtime % G_USEC_PER_SEC),
						packet_size, packet_size, packet, &bytes_written, &err)) {
					g_debug("Error in libpcap_write_packet(): %s", g_strerror(err));
					break;
				}
				g_debug("Dumped packet %lu size: %u", packets, packet_size);
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
			g_debug("Current IOS Version: %u.%u", major, minor);
			if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
				return FALSE;
			return TRUE;
		}
	}

	g_warning("Invalid IOS version. Minimum version: 12.4, current: %u.%u", major, minor);
	return FALSE;
}

static ssh_channel run_capture(ssh_session sshs, const char* iface, const char* cfilter, const guint32 count)
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

	if (ssh_channel_printf(channel, "monitor capture buffer %s limit packet-count %u\n", WIRESHARK_CAPTURE_BUFFER, count) == EXIT_FAILURE)
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
			g_debug("Splitting filter into multiline");
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
	g_warning("Error running ssh remote command");
	read_output_bytes(channel, -1, NULL);

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return NULL;
}

static int ssh_open_remote_connection(const ssh_params_t* ssh_params, const char* iface, const char* cfilter,
	const guint32 count, const char* fifo)
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
		fp = fopen(fifo, "wb");
		if (!fp) {
			g_warning("Error creating output file: %s", g_strerror(errno));
			return EXIT_FAILURE;
		}
	}

	sshs = create_ssh_connection(ssh_params, &err_info);
	if (!sshs) {
		g_warning("Error creating connection: %s", err_info);
		goto cleanup;
	}

	if (!libpcap_write_file_header(fp, 1, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
		g_warning("Can't write pcap file header");
		goto cleanup;
	}

	channel = run_capture(sshs, iface, cfilter, count);
	if (!channel) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* read from channel and write into fp */
	ssh_loop_read(channel, fp, count);

	/* clean up and exit */
	ciscodump_cleanup(sshs, channel, iface, cfilter);

	ret = EXIT_SUCCESS;
cleanup:
	if (fp != stdout)
		fclose(fp);

	return ret;
}

static int list_config(char *interface, unsigned int remote_port)
{
	unsigned inc = 0;
	char* ipfilter;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, CISCODUMP_EXTCAP_INTERFACE)) {
		g_warning("interface must be %s", CISCODUMP_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	ipfilter = local_interfaces_to_filter(remote_port);

	printf("arg {number=%u}{call=--remote-host}{display=Remote SSH server address}"
		"{type=string}{tooltip=The remote SSH host. It can be both "
		"an IP address or a hostname}{required=true}{group=Server}\n", inc++);
	printf("arg {number=%u}{call=--remote-port}{display=Remote SSH server port}"
		"{type=unsigned}{default=22}{tooltip=The remote SSH host port (1-65535)}"
		"{range=1,65535}{group=Server}\n", inc++);
	printf("arg {number=%u}{call=--remote-username}{display=Remote SSH server username}"
		"{type=string}{default=%s}{tooltip=The remote SSH username. If not provided, "
		"the current user will be used}{group=Authentication}\n", inc++, g_get_user_name());
	printf("arg {number=%u}{call=--remote-password}{display=Remote SSH server password}"
		"{type=password}{tooltip=The SSH password, used when other methods (SSH agent "
		"or key files) are unavailable.}{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call=--sshkey}{display=Path to SSH private key}"
		"{type=fileselect}{tooltip=The path on the local filesystem of the private ssh key}"
		"{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call=--proxycommand}{display=ProxyCommand}"
		"{type=string}{tooltip=The command to use as proxy for the SSH connection}"
		"{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call--sshkey-passphrase}{display=SSH key passphrase}"
		"{type=password}{tooltip=Passphrase to unlock the SSH private key}"
		"{group=Authentication\n", inc++);
	printf("arg {number=%u}{call=--remote-interface}{display=Remote interface}"
		"{type=string}{required=true}{tooltip=The remote network interface used for capture"
		"}{group=Capture}\n", inc++);
	printf("arg {number=%u}{call=--remote-filter}{display=Remote capture filter}"
		"{type=string}{tooltip=The remote capture filter}", inc++);
	if (ipfilter)
		printf("{default=%s}", ipfilter);
	printf("{group=Capture}\n");
	printf("arg {number=%u}{call=--remote-count}{display=Packets to capture}"
		"{type=unsigned}{required=true}{tooltip=The number of remote packets to capture.}"
		"{group=Capture}\n", inc++);

	extcap_config_debug(&inc);

	g_free(ipfilter);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	char* err_msg;
	int result;
	int option_idx = 0;
	ssh_params_t* ssh_params = ssh_params_new();
	char* remote_interface = NULL;
	char* remote_filter = NULL;
	guint32 count = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters * extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	err_msg = init_progfile_dir(argv[0]);
	if (err_msg != NULL) {
		g_warning("Can't get pathname of directory containing the captype program: %s.",
			err_msg);
		g_free(err_msg);
	}

	help_url = data_file_url("ciscodump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], CISCODUMP_VERSION_MAJOR, CISCODUMP_VERSION_MINOR,
		CISCODUMP_VERSION_RELEASE, help_url);
	add_libssh_info(extcap_conf);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, CISCODUMP_EXTCAP_INTERFACE, "Cisco remote capture", 147, "Remote capture dependent DLT");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --remote-host myhost --remote-port 22222 "
		"--remote-username myuser --remote-interface gigabit0/0 "
		"--fifo=FILENAME --capture\n", argv[0], argv[0], CISCODUMP_EXTCAP_INTERFACE, argv[0],
		CISCODUMP_EXTCAP_INTERFACE, argv[0], CISCODUMP_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);

	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--remote-host <host>", "the remote SSH host");
	extcap_help_add_option(extcap_conf, "--remote-port <port>", "the remote SSH port (default: 22)");
	extcap_help_add_option(extcap_conf, "--remote-username <username>", "the remote SSH username (default: the current user)");
	extcap_help_add_option(extcap_conf, "--remote-password <password>", "the remote SSH password. "
		"If not specified, ssh-agent and ssh-key are used");
	extcap_help_add_option(extcap_conf, "--sshkey <public key path>", "the path of the ssh key");
	extcap_help_add_option(extcap_conf, "--sshkey-passphrase <public key passphrase>", "the passphrase to unlock public ssh");
	extcap_help_add_option(extcap_conf, "--proxycommand <proxy command>", "the command to use as proxy the the ssh connection");
	extcap_help_add_option(extcap_conf, "--remote-interface <iface>", "the remote capture interface");
	extcap_help_add_option(extcap_conf, "--remote-filter <filter>", "a filter for remote capture "
		"(default: don't capture data for lal interfaces IPs)");

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
			extcap_version_print(extcap_conf);
			goto end;

		case OPT_REMOTE_HOST:
			g_free(ssh_params->host);
			ssh_params->host = g_strdup(optarg);
			break;

		case OPT_REMOTE_PORT:
			if (!ws_strtou16(optarg, NULL, &ssh_params->port) || ssh_params->port == 0) {
				g_warning("Invalid port: %s", optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_USERNAME:
			g_free(ssh_params->username);
			ssh_params->username = g_strdup(optarg);
			break;

		case OPT_REMOTE_PASSWORD:
			g_free(ssh_params->password);
			ssh_params->password = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_SSHKEY:
			g_free(ssh_params->sshkey_path);
			ssh_params->sshkey_path = g_strdup(optarg);
			break;

		case OPT_SSHKEY_PASSPHRASE:
			g_free(ssh_params->sshkey_passphrase);
			ssh_params->sshkey_passphrase = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case OPT_PROXYCOMMAND:
			g_free(ssh_params->proxycommand);
			ssh_params->proxycommand = g_strdup(optarg);
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
			if (!ws_strtou32(optarg, NULL, &count)) {
				g_warning("Invalid packet count: %s", optarg);
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

	extcap_cmdline_debug(argv, argc);

	if (optind != argc) {
		g_warning("Unexpected extra option: %s", argv[optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface, ssh_params->port);
		goto end;
	}

	err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		g_warning("ERROR: %s", err_msg);
                g_free(err_msg);
		g_warning("%s", please_report_bug());
		goto end;
	}

	if (extcap_conf->capture) {
		if (!ssh_params->host) {
			g_warning("Missing parameter: --remote-host");
			goto end;
		}

		if (!remote_interface) {
			g_warning("ERROR: No interface specified (--remote-interface)");
			goto end;
		}
		if (count == 0) {
			g_warning("ERROR: count of packets must be specified (--remote-count)");
			goto end;
		}
		ssh_params->debug = extcap_conf->debug;
		ret = ssh_open_remote_connection(ssh_params, remote_interface,
			remote_filter, count, extcap_conf->fifo);
	} else {
		g_debug("You should not come here... maybe some parameter missing?");
		ret = EXIT_FAILURE;
	}

end:
	ssh_params_free(ssh_params);
	g_free(remote_interface);
	g_free(remote_filter);
	extcap_base_cleanup(&extcap_conf);
	return ret;
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
