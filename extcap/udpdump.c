/* udpdump.c
 * udpdump is an extcap tool used to get packets exported from a source (like a network device or a GSMTAP producer) that
 * are dumped to a pcap file
 *
 * Copyright 2016, Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <extcap/extcap-base.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TIME_H
	#include <sys/time.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#endif

#include <writecap/pcapio.h>
#include <wiretap/wtap.h>
#include <wsutil/strtoi.h>
#include <wsutil/inet_addr.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>
#include <wsutil/please_report_bug.h>

#include <cli_main.h>

#define PCAP_SNAPLEN 0xffff

#define UDPDUMP_DEFAULT_PORT 5555

#define UDPDUMP_EXTCAP_INTERFACE "udpdump"
#define UDPDUMP_VERSION_MAJOR "0"
#define UDPDUMP_VERSION_MINOR "1"
#define UDPDUMP_VERSION_RELEASE "0"

#define PKT_BUF_SIZE 65535

#define UDPDUMP_EXPORT_HEADER_LEN 40

/* Tags (from exported_pdu.h) */
#define EXP_PDU_TAG_PROTO_NAME	12
#define EXP_PDU_TAG_IPV4_SRC	20
#define EXP_PDU_TAG_IPV4_DST	21
#define EXP_PDU_TAG_SRC_PORT	25
#define EXP_PDU_TAG_DST_PORT	26

static gboolean run_loop = TRUE;

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_PORT,
	OPT_PAYLOAD
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	/* Generic application options */
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	/* Interfaces options */
	{ "port", required_argument, NULL, OPT_PORT},
	{ "payload", required_argument, NULL, OPT_PAYLOAD},
    { 0, 0, 0, 0 }
};

static int list_config(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--port}{display=Listen port}"
		"{type=unsigned}{range=1,65535}{default=%u}{tooltip=The port the receiver listens on}\n",
		inc++, UDPDUMP_DEFAULT_PORT);
	printf("arg {number=%u}{call=--payload}{display=Payload type}"
		"{type=string}{default=data}{tooltip=The type used to describe the payload in the exported pdu format}\n",
		inc++);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

static int setup_listener(const guint16 port, socket_handle_t* sock)
{
	int optval;
	struct sockaddr_in serveraddr;
#ifndef _WIN32
	struct timeval timeout = { 1, 0 };
#endif

	*sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (*sock == INVALID_SOCKET) {
		g_warning("Error opening socket: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	optval = 1;
	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, (socklen_t)sizeof(int)) < 0) {
		g_warning("Can't set socket option SO_REUSEADDR: %s", strerror(errno));
		goto cleanup_setup_listener;
	}

#ifndef _WIN32
	if (setsockopt (*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, (socklen_t)sizeof(timeout)) < 0) {
		g_warning("Can't set socket option SO_RCVTIMEO: %s", strerror(errno));
		goto cleanup_setup_listener;
	}
#endif

	memset(&serveraddr, 0x0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(port);

	if (bind(*sock, (struct sockaddr *)&serveraddr, (socklen_t)sizeof(serveraddr)) < 0) {
		g_warning("Error on binding: %s", strerror(errno));
		goto cleanup_setup_listener;
	}

	return EXIT_SUCCESS;

cleanup_setup_listener:
	closesocket(*sock);
	return EXIT_FAILURE;

}

static void exit_from_loop(int signo _U_)
{
	g_warning("Exiting from main loop");
	run_loop = FALSE;
}

static int setup_dumpfile(const char* fifo, FILE** fp)
{
	guint64 bytes_written = 0;
	int err;

	if (!g_strcmp0(fifo, "-")) {
		*fp = stdout;
		return EXIT_SUCCESS;
	}

	*fp = fopen(fifo, "wb");
	if (!(*fp)) {
		g_warning("Error creating output file: %s", g_strerror(errno));
		return EXIT_FAILURE;
	}

	if (!libpcap_write_file_header(*fp, 252, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
		g_warning("Can't write pcap file header: %s", g_strerror(err));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void add_proto_name(guint8* mbuf, guint* offset, const char* proto_name)
{
	size_t proto_str_len = strlen(proto_name);
	guint16 proto_name_len = (guint16)((proto_str_len + 3) & 0xfffffffc);

	mbuf[*offset] = 0;
	mbuf[*offset+1] = EXP_PDU_TAG_PROTO_NAME;
	*offset += 2;
	mbuf[*offset] = proto_name_len >> 8;
	mbuf[*offset+1] = proto_name_len & 0xff;
	*offset += 2;

	memcpy(mbuf + *offset, proto_name, proto_str_len);
	*offset += proto_name_len;
}

static void add_ip_source_address(guint8* mbuf, guint* offset, uint32_t source_address)
{
	mbuf[*offset] = 0x00;
	mbuf[*offset+1] = EXP_PDU_TAG_IPV4_SRC;
	mbuf[*offset+2] = 0;
	mbuf[*offset+3] = 4;
	*offset += 4;
	memcpy(mbuf + *offset, &source_address, 4);
	*offset += 4;
}

static void add_ip_dest_address(guint8* mbuf, guint* offset, uint32_t dest_address)
{
	mbuf[*offset] = 0;
	mbuf[*offset+1] = EXP_PDU_TAG_IPV4_DST;
	mbuf[*offset+2] = 0;
	mbuf[*offset+3] = 4;
	*offset += 4;
	memcpy(mbuf + *offset, &dest_address, 4);
	*offset += 4;
}

static void add_udp_source_port(guint8* mbuf, guint* offset, uint16_t src_port)
{
	uint32_t port = htonl(src_port);

	mbuf[*offset] = 0;
	mbuf[*offset+1] = EXP_PDU_TAG_SRC_PORT;
	mbuf[*offset+2] = 0;
	mbuf[*offset+3] = 4;
	*offset += 4;
	memcpy(mbuf + *offset, &port, 4);
	*offset += 4;
}

static void add_udp_dst_port(guint8* mbuf, guint* offset, uint16_t dst_port)
{
	uint32_t port = htonl(dst_port);

	mbuf[*offset] = 0;
	mbuf[*offset+1] = EXP_PDU_TAG_DST_PORT;
	mbuf[*offset+2] = 0;
	mbuf[*offset+3] = 4;
	*offset += 4;
	memcpy(mbuf + *offset, &port, 4);
	*offset += 4;
}

static void add_end_options(guint8* mbuf, guint* offset)
{
	memset(mbuf + *offset, 0x0, 4);
	*offset += 4;
}

static int dump_packet(const char* proto_name, const guint16 listenport, const char* buf,
		const ssize_t buflen, const struct sockaddr_in clientaddr, FILE* fp)
{
	guint8* mbuf;
	guint offset = 0;
	gint64 curtime = g_get_real_time();
	guint64 bytes_written = 0;
	int err;
	int ret = EXIT_SUCCESS;

	/* The space we need is the standard header + variable lengths */
	mbuf = (guint8*)g_malloc0(UDPDUMP_EXPORT_HEADER_LEN + ((strlen(proto_name) + 3) & 0xfffffffc) + buflen);

	add_proto_name(mbuf, &offset, proto_name);
	add_ip_source_address(mbuf, &offset, clientaddr.sin_addr.s_addr);
	add_ip_dest_address(mbuf, &offset, WS_IN4_LOOPBACK);
	add_udp_source_port(mbuf, &offset, clientaddr.sin_port);
	add_udp_dst_port(mbuf, &offset, listenport);
	add_end_options(mbuf, &offset);

	memcpy(mbuf + offset, buf, buflen);
	offset += (guint)buflen;

	if (!libpcap_write_packet(fp,
			(guint32)(curtime / G_USEC_PER_SEC), (guint32)(curtime % G_USEC_PER_SEC),
			offset, offset, mbuf, &bytes_written, &err)) {
		g_warning("Can't write packet: %s", g_strerror(err));
		ret = EXIT_FAILURE;
	}

	fflush(fp);

	g_free(mbuf);
	return ret;
}

static void run_listener(const char* fifo, const guint16 port, const char* proto_name)
{
	struct sockaddr_in clientaddr;
	socklen_t clientlen = sizeof(clientaddr);
	socket_handle_t sock;
	char* buf;
	ssize_t buflen;
	FILE* fp = NULL;

	if (signal(SIGINT, exit_from_loop) == SIG_ERR) {
		g_warning("Can't set signal handler");
		return;
	}

	if (setup_dumpfile(fifo, &fp) == EXIT_FAILURE) {
		if (fp)
			fclose(fp);
		return;
	}

	if (setup_listener(port, &sock) == EXIT_FAILURE)
		return;

	g_debug("Listener running on port %u", port);

	buf = (char*)g_malloc(PKT_BUF_SIZE);
	while(run_loop == TRUE) {
		memset(buf, 0x0, PKT_BUF_SIZE);

		buflen = recvfrom(sock, buf, PKT_BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if (buflen < 0) {
			switch(errno) {
				case EAGAIN:
				case EINTR:
					break;
				default:
#ifdef _WIN32
					{
						wchar_t *errmsg = NULL;
						int err = WSAGetLastError();
						FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
							NULL, err,
							MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
							(LPWSTR)&errmsg, 0, NULL);
						g_warning("Error in recvfrom: %S (err=%d)", errmsg, err);
						LocalFree(errmsg);
					}
#else
					g_warning("Error in recvfrom: %s (errno=%d)", strerror(errno), errno);
#endif
					run_loop = FALSE;
					break;
			}
		} else {
			if (dump_packet(proto_name, port, buf, buflen, clientaddr, fp) == EXIT_FAILURE)
				run_loop = FALSE;
		}
	}

	fclose(fp);
	closesocket(sock);
	g_free(buf);
}

int main(int argc, char *argv[])
{
	char* err_msg;
	int option_idx = 0;
	int result;
	guint16 port = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;
	char* payload = NULL;
	char* port_msg = NULL;

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

	help_url = data_file_url("udpdump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], UDPDUMP_VERSION_MAJOR, UDPDUMP_VERSION_MINOR, UDPDUMP_VERSION_RELEASE,
		help_url);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, UDPDUMP_EXTCAP_INTERFACE, "UDP Listener remote capture", 252, "Exported PDUs");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --port 5555 --fifo myfifo --capture",
		argv[0], argv[0], UDPDUMP_EXTCAP_INTERFACE, argv[0], UDPDUMP_EXTCAP_INTERFACE, argv[0], UDPDUMP_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	port_msg = g_strdup_printf("the port to listens on. Default: %u", UDPDUMP_DEFAULT_PORT);
	extcap_help_add_option(extcap_conf, "--port <port>", port_msg);
	g_free(port_msg);

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

		case OPT_PORT:
			if (!ws_strtou16(optarg, NULL, &port)) {
				g_warning("Invalid port: %s", optarg);
				goto end;
			}
			break;

		case OPT_PAYLOAD:
			g_free(payload);
			payload = g_strdup(optarg);
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
		ret = list_config(extcap_conf->interface);
		goto end;
	}

	if (!payload)
		payload = g_strdup("data");

	err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		g_warning("Error: %s", err_msg);
		g_free(err_msg);
		g_warning("%s", please_report_bug());
		goto end;
	}

	if (port == 0)
		port = UDPDUMP_DEFAULT_PORT;

	if (extcap_conf->capture)
		run_listener(extcap_conf->fifo, port, payload);

end:
	/* clean up stuff */
	extcap_base_cleanup(&extcap_conf);
	g_free(payload);
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
