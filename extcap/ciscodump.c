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
#define WS_LOG_DOMAIN "ciscodump"

#include <extcap/extcap-base.h>
#include <wsutil/interface.h>
#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>
#include <extcap/ssh-base.h>
#include <writecap/pcapio.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <wsutil/time_util.h>

#include <cli_main.h>

#define CISCODUMP_VERSION_MAJOR "1"
#define CISCODUMP_VERSION_MINOR "0"
#define CISCODUMP_VERSION_RELEASE "0"

/* The read timeout in msec */
#define CISCODUMP_READ_TIMEOUT_MSEC 300

#define CISCODUMP_EXTCAP_INTERFACE "ciscodump"
#define SSH_READ_BLOCK_SIZE 1024
#define SSH_READ_TIMEOUT_MSES 10000
#define SSH_READ_TIMEOUT_USEC (SSH_READ_TIMEOUT_MSES*1000)

#define WIRESHARK_CAPTURE "WSC"
#define WIRESHARK_CAPTURE_POINT "WSC_P"
#define WIRESHARK_CAPTURE_BUFFER "WSC_B"
#define WIRESHARK_CAPTURE_ACCESSLIST "WSC_ACL"

#define PCAP_SNAPLEN 0xffff

#define PACKET_MAX_SIZE 65535

#define MINIMUM_IOS_MAJOR 12
#define MINIMUM_IOS_MINOR 4
#define MINIMUM_IOS_XE_MAJOR 16
#define MINIMUM_IOS_XE_MINOR 1
#define MINIMUM_ASA_MAJOR 8
#define MINIMUM_ASA_MINOR 4

#define READ_PROMPT_ERROR -1
#define READ_PROMPT_EOLN 0
#define READ_PROMPT_PROMPT 1
#define READ_PROMPT_TOO_LONG 2

#define READ_LINE_ERROR -1
#define READ_LINE_EOLN 0
#define READ_LINE_TIMEOUT 1
#define READ_LINE_TOO_LONG 2

/* Type of Cisco device */
typedef enum {
	CISCO_UNKNOWN,
	CISCO_IOS,
	CISCO_IOS_XE,
	CISCO_ASA
} CISCO_SW_TYPE;

/* Status of the parser */
enum {
	CISCODUMP_PARSER_STARTING,
	CISCODUMP_PARSER_IN_PACKET,
	CISCODUMP_PARSER_IN_HEADER,
	CISCODUMP_PARSER_END_PACKET,
	CISCODUMP_PARSER_UNKNOWN
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

static char prompt_str[SSH_READ_BLOCK_SIZE + 1];
static gint32 prompt_len = -1;

static gboolean end_application = FALSE;

static struct ws_option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", ws_no_argument, NULL, OPT_HELP},
	{ "version", ws_no_argument, NULL, OPT_VERSION},
	SSH_BASE_OPTIONS,
	{ 0, 0, 0, 0}
};

#ifdef _WIN32
static BOOL WINAPI
exit_from_loop(DWORD dwCtrlType _U_)
#else
static void exit_from_loop(int signo _U_)
#endif /* _WIN32 */
{
#ifndef _WIN32
	/* Disable signal reception after first signal to avoid signal storms */
	signal(signo, SIG_IGN);
#endif /* _WIN32 */
	ws_warning("Exiting from main loop");
	end_application = TRUE;
#ifdef _WIN32
	return TRUE;
#endif /* _WIN32 */
}

/* Replaces needle with rep in line */
static char* str_replace_char(char *line, char needle, char rep)
{
	for(int i = 0; line[i] != '\0'; i++) {
		if (line[i] == needle) {
			line[i] = rep;
		}
	}

	return line;
}

/* Replaces CR with LN */
static char* crtoln(char *line)
{
	return str_replace_char(line, '\r', '\n');
}

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

/* Read bytes from the channel with no escape character.
 * If bytes == -1, read all data (until timeout). If outbuf != NULL, data are stored there
 */
static int read_output_bytes_any(ssh_channel channel, int bytes, char* outbuf)
{
	char chr;
	int total;
	int bytes_read;

	total = (bytes > 0 ? bytes : G_MAXINT);
	bytes_read = 0;

	while(ssh_channel_read_timeout(channel, &chr, 1, 0, CISCODUMP_READ_TIMEOUT_MSEC) > 0 && bytes_read < total) {
		ws_noisy("%c %02x", chr, chr);
		if (outbuf)
			outbuf[bytes_read] = chr;
		bytes_read++;
	}
	if (outbuf)
		outbuf[bytes_read+1] = '\0';
	return EXIT_SUCCESS;
}

/* Read bytes from the channel. Recognize escape char '^'.
 * If bytes == -1, read all data (until timeout). If outbuf != NULL, data are stored there
 */
static int read_output_bytes(ssh_channel channel, int bytes, char* outbuf)
{
	char chr;
	int total;
	int bytes_read;

	total = (bytes > 0 ? bytes : G_MAXINT);
	bytes_read = 0;

	while(ssh_channel_read_timeout(channel, &chr, 1, 0, CISCODUMP_READ_TIMEOUT_MSEC) > 0 && bytes_read < total) {
		ws_noisy("%c %02x", chr, chr);
		if (chr == '^')
			return EXIT_FAILURE;
		if (outbuf)
			outbuf[bytes_read] = chr;
		bytes_read++;
	}
	return EXIT_SUCCESS;
}

/* Reads input to buffer and parses EOL
 *   If line is NULL, just received count of characters in len is calculated
 * It returns:
 *   READ_LINE_ERROR - any ssh error occured
 *   READ_LINE_EOLN - EOLN found, line/len contains \0 terminated string
 *   READ_LINE_TIMEOUT - reading ended with timeout, line/len contains \0 terminate prompt
 *   READ_LINE_TOO_LONG - buffer is full with no EOLN nor PROMPT found, line is filled with NOT \0 terminated data
 */
static int ssh_channel_read_line_timeout(ssh_channel channel, char *line, int *len, int max_len) {
	char chr;
	int rlen = 0;

	*len = 0;
	do {
		rlen = ssh_channel_read_timeout(channel, &chr, 1, FALSE, CISCODUMP_READ_TIMEOUT_MSEC);
		ws_noisy("%c %02x %d", chr, chr, rlen);
		if (rlen == SSH_ERROR) {
			ws_warning("Error reading from channel");
			return READ_LINE_ERROR;
		} else if (rlen > 0) {
			if (chr != '\n') {
				/* Ignore \r */
				if (chr != '\r') {
					if (line) {
						line[*len] = chr;
					}
					(*len)++;
				}
			} else {
				/* Parse the current line */
				if (line) {
					line[*len] = '\0';
				}
				return READ_LINE_EOLN;
			}
		} else {
			return READ_LINE_TIMEOUT;
		}
	} while (*len < max_len);

	return READ_LINE_TOO_LONG;
}

/* Reads input to buffer and parses EOL or prompt_str PROMPT
 * It returns:
 *   READ_PROMPT_ERROR - any ssh error occured
 *   READ_PROMPT_EOLN - EOLN found, line/len contains \0 terminated string
 *   READ_PROMPT_PROMPT - reading ended and it ends with PROMPT, line/len contains \0 terminate prompt
 *   READ_PROMPT_TOO_LONG - buffer is full with no EOLN nor PROMPT found, line is filled with NOT \0 terminated data
 */
static int ssh_channel_read_prompt(ssh_channel channel, char *line, guint32 *len, guint32 max_len) {
	char chr;
	int rlen = 0;
	gint64 start_time = g_get_monotonic_time();

	do {
		rlen = ssh_channel_read_timeout(channel, &chr, 1, FALSE, CISCODUMP_READ_TIMEOUT_MSEC);
		ws_noisy("%c %02x %d", chr, chr, rlen);
		if (rlen == SSH_ERROR) {
			ws_warning("Error reading from channel");
			return READ_PROMPT_ERROR;
		} else if (rlen > 0) {
			if (chr != '\n') {
				line[*len] = chr;
				(*len)++;
			} else {
				/* Parse the current line */
				line[*len] = '\0';
				return READ_PROMPT_EOLN;
			}
		} else {
			gint64 cur_time = g_get_monotonic_time();

			/* ssh timeout, we might be on prompt */
			/* IOS, IOS-XE: check if line has same length as prompt and if it match prompt */
			if ((*len == (guint32)prompt_len) && (0 == strncmp(line, prompt_str, prompt_len))) {
				line[*len] = '\0';
				return READ_PROMPT_PROMPT;
			}
			/* ASA: check if line begins with \r and has same length as prompt and if it match prompt */
			if ((line[0] == '\r') && (*len == (guint32)prompt_len+1) && (0 == strncmp(line+1, prompt_str, prompt_len))) {
				line[*len] = '\0';
				return READ_PROMPT_PROMPT;
			}
			/* no prompt found, so we continue in waiting for data, but we should check global timeout */
			if ((cur_time-start_time) > SSH_READ_TIMEOUT_USEC) {
				line[*len] = '\0';
				return READ_PROMPT_ERROR;
			}
		}
	} while (!end_application && (*len < max_len));

	line[*len] = '\0';
	return READ_PROMPT_TOO_LONG;
}

static int ssh_channel_wait_prompt(ssh_channel channel, char *line, guint32 *len, guint32 max_len) {
	char line2[SSH_READ_BLOCK_SIZE + 1];
	guint32 len2;
	int status;

	memset(line2, 0x0, SSH_READ_BLOCK_SIZE + 1);
	line[0] = '\0';
	*len = 0;
	do {
		len2 = 0;
		switch (status = ssh_channel_read_prompt(channel, line2, &len2, SSH_READ_BLOCK_SIZE)) {
			case READ_PROMPT_EOLN:
				*len = (guint32)g_strlcat(line, line2, max_len);
				len2 = 0;
				break;
			case READ_PROMPT_PROMPT:
				*len = (guint32)g_strlcat(line, line2, max_len);
				len2 = 0;
				break;
			default:
				/* We do not have better solution for that cases */
				/* Just terminate the line and return error */
				*len = (guint32)g_strlcat(line, line2, max_len);
				line[max_len] = '\0';
				return READ_PROMPT_ERROR;
		}
	} while (status == READ_PROMPT_EOLN);

	return READ_PROMPT_PROMPT;
}

/* TRUE if prompt and no error text in response. FALSE otherwise */
/* Note: It do not catch all CISCO CLI errors, but many of them */
static gboolean ssh_channel_wait_prompt_check_error(ssh_channel channel, char *line, guint32 *len, guint32 max_len, char *error_re) {
	/* Did we received prompt? */
	if (ssh_channel_wait_prompt(channel, line, len, max_len) != READ_PROMPT_PROMPT) {
		return FALSE;
	}

	/* Is there ERROR: text in output? */
	if (NULL != g_strstr_len(line, -1, "ERROR:")) {
		return FALSE;
	}

	/* Is there ERROR: text in output? */
	if (NULL != g_strstr_len(line, -1, "% Invalid input detected at")) {
		return FALSE;
	}

	/* Is there error_re text in output? */
	if (error_re &&
	    g_regex_match_simple(error_re, line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)
	   ) {
		return FALSE;
	}

	return TRUE;
}

static void ciscodump_cleanup_ios(ssh_channel channel, const char* iface, const char* cfilter)
{
	gchar* iface_copy = g_strdup(iface);
	gchar* iface_one;
	gchar* str = NULL;
	int wscp_cnt = 1;
	gchar* wscp_str = NULL;

	end_application = FALSE;
	if (channel) {
		ws_debug("Removing configuration...");
		read_output_bytes(channel, -1, NULL);

		wscp_cnt = 1;
		for (str = iface_copy; ; str = NULL) {
			iface_one = strtok(str, ",");
			if (iface_one == NULL)
				break;

			wscp_str = g_strdup_printf("%s_%d", WIRESHARK_CAPTURE_POINT, wscp_cnt);
			wscp_cnt++;

			ssh_channel_printf(channel, "monitor capture point stop %s\n", wscp_str);
			ssh_channel_printf(channel, "no monitor capture point ip cef %s %s\n", wscp_str, iface_one);

			g_free(wscp_str);
			wscp_str = NULL;
		}

		ssh_channel_printf(channel, "no monitor capture buffer %s\n", WIRESHARK_CAPTURE_BUFFER);
		if (cfilter) {
			ssh_channel_printf(channel, "configure terminal\n");
			ssh_channel_printf(channel, "no ip access-list ex %s\n", WIRESHARK_CAPTURE_ACCESSLIST);
		}

		read_output_bytes(channel, -1, NULL);
		ws_debug("Configuration removed");
	}

	g_free(iface_copy);
}

static void ciscodump_cleanup_ios_xe(ssh_channel channel, const char* cfilter)
{
	if (channel) {
		ws_debug("Removing configuration...");
		read_output_bytes(channel, -1, NULL);

		ssh_channel_printf(channel, "monitor capture %s stop\n", WIRESHARK_CAPTURE);
		ssh_channel_printf(channel, "no monitor capture %s\n", WIRESHARK_CAPTURE);
		if (cfilter) {
			ssh_channel_printf(channel, "configure terminal\n");
			ssh_channel_printf(channel, "no ip access-list extended %s\n", WIRESHARK_CAPTURE_ACCESSLIST);
			ssh_channel_printf(channel, "\nend\n");
		}

		read_output_bytes(channel, -1, NULL);
		ws_debug("Configuration removed");
	}
}

static void ciscodump_cleanup_asa(ssh_channel channel, const char* cfilter)
{
	if (channel) {
		ws_debug("Removing configuration...");
		read_output_bytes(channel, -1, NULL);

		ssh_channel_printf(channel, "no capture %s\n", WIRESHARK_CAPTURE);
		if (cfilter) {
			ssh_channel_printf(channel, "configure terminal\n");
			ssh_channel_printf(channel, "clear configure access-list %s\n", WIRESHARK_CAPTURE_ACCESSLIST);
			ssh_channel_printf(channel, "\nend\n", WIRESHARK_CAPTURE_ACCESSLIST);
		}

		read_output_bytes(channel, -1, NULL);
		ws_debug("Configuration removed");
	}
}

static void ciscodump_cleanup(ssh_channel channel, const char* iface, const char* cfilter, CISCO_SW_TYPE sw_type)
{
	ws_debug("Starting config cleanup");
	switch (sw_type) {
		case CISCO_IOS:
			ciscodump_cleanup_ios(channel, iface, cfilter);
			break;
		case CISCO_IOS_XE:
			ciscodump_cleanup_ios_xe(channel, cfilter);
			break;
		case CISCO_ASA:
			ciscodump_cleanup_asa(channel, cfilter);
			break;
		case CISCO_UNKNOWN:
			break;
	}
	ws_debug("Config cleanup finished");
}

static void packets_captured_count_ios(char *line, guint32 *max, gboolean *running) {
	char** part;

	*max = 0;

	ws_debug("Analyzing response: %s", line);

	/* Read count of packets */
	part = g_regex_split_simple(
		"Packets :\\s*(\\d+)",
		line, G_REGEX_CASELESS, 0);
	if (*part && *(part+1)) {
		/* RE matched */
		if (strlen(*(part+1)) > 0) {
			ws_strtou32(*(part+1), NULL, max);
		}
	}
	g_strfreev(part);

	*running = FALSE;
	if (g_regex_match_simple("Status : Active", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)) {
		*running = TRUE;
	}
	ws_debug("Count of packets: %d", *max);
	ws_debug("Capture is running: %d", *running);
}

static void packets_captured_count_ios_xe(char *line, guint32 *max, gboolean *running) {
	char** part;

	*max = 0;

	ws_debug("Analyzing response: %s", line);

	part = g_regex_split_simple(
		"packets in buf\\s+:\\s+(\\d+)",
		line, G_REGEX_CASELESS, 0);
	if (*part && *(part+1)) {
		/* RE matched */
		if (strlen(*(part+1)) > 0) {
			ws_strtou32(*(part+1), NULL, max);
		}
	}
	g_strfreev(part);

	*running = FALSE;
	/* Check if capture is running */
	if (g_regex_match_simple("Status : Active", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)) {
		*running = TRUE;
	}
	ws_debug("Count of packets: %d", *max);
	ws_debug("Capture is running: %d", *running);
}

static void packets_captured_count_asa(char *line, guint32 *max, gboolean *running) {
	char** part;

	*max = 0;

	ws_debug("Analyzing response: %s", line);

	/* Read count of packets */
	part = g_regex_split_simple(
		"(\\d+) packets captured",
		line, G_REGEX_CASELESS, 0);
	if (*part && *(part+1)) {
		/* RE matched */
		if (strlen(*(part+1)) > 0) {
			ws_strtou32(*(part+1), NULL, max);
		}
	}
	g_strfreev(part);

        if (running != NULL) {
		*running = FALSE;
		/* Check if capture is running */
		if (g_regex_match_simple("\\[Capturing -", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)) {
			*running = TRUE;
		}
		ws_debug("Capture is running: %d", *running);
	}
	ws_debug("Count of packets: %d", *max);
}

static int parse_line_ios(guint8* packet, unsigned* offset, char* line, int status, time_t *pkt_time, guint32 *pkt_usec)
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

/*
22:45:44.700 UTC Nov 27 2021 : IPv4 LES CEF    : Fa4.320 None

0F1A2C00:                   B0FAEBC7 A8620050          0zkG(b.P
0F1A2C10: 568494FB 08004588 004EF201 40003F11  V..{..E..Nr.@.?.
0F1A2C20: 5263AC10 1F60AC10 7F31D0DF 00A1003A  Rc,..`,..1P_.!.:
0F1A2C30: D1753030 02010104 07707269 76617465  Qu00.....private
0F1A2C40: A0220204 1A00A2E8 02010002 01003014   "...."h......0.
0F1A2C50: 3012060E 2B060104 0182CB21 01040103  0...+.....K!....
0F1A2C60: 06000500 00                          .....

22:45:44.700 UTC Nov 27 2021 : IPv4 LES CEF    : Fa4.320 None

0F1A2C00:                   B0FAEBC7 A8620050          0zkG(b.P
0F1A2C10: 568494FB 08004588 004E7FFB 40003F11  V..{..E..N.{@.?.
0F1A2C20: EB72AC10 1F60AC10 5828E872 00A1003A  kr,..`,.X(hr.!.:
0F1A2C30: 2B393030 02010104 07707269 76617465  +900.....private
0F1A2C40: A0220204 07836B18 02010002 01003014   "....k.......0.
0F1A2C50: 3012060E 2B060104 0182CB21 01040103  0...+.....K!....
0F1A2C60: 06000500 00                          .....
*/

	/* we got the packet header                                    */
	/* The packet header is a line like:                           */
	/* 16:09:37.171 ITA Mar 18 2016 : IPv4 LES CEF    : Gi0/1 None */
	parts = g_regex_split_simple(
		"^(\\d{2}:\\d{2}:\\d{2}).(\\d+) (\\w+) (\\w+ \\d+ \\d+) :",
		line, G_REGEX_CASELESS, 0);
	if (parts && *(parts+1)) {
		/* RE matched */
		gchar* cp;
		struct tm tm;
		/* Date without msec, with timezone */
		gchar* d1 = g_strdup_printf("%s %s %s", *(parts+1), *(parts+3), *(parts+4));
		/* Date without msec, without timezone */
		gchar* d2 = g_strdup_printf("%s %s", *(parts+1), *(parts+4));

		memset(&tm, 0x0, sizeof(struct tm));

		cp = ws_strptime(d1, "%H:%M:%S %Z %b %d %Y", &tm);
		if (!cp || (*cp != '\0')) {
			/* Time zone parse failed */
			cp = ws_strptime(d2, "%H:%M:%S %b %d %Y", &tm);
			if (!cp || (*cp != '\0')) {
				/* Time parse failed, use now */
				time_t t;
				struct tm *tm2;

				t = time(0);
				tm2 = localtime(&t);
				memcpy(&tm, tm2, sizeof(struct tm));
			}
		}
		ws_strtou32(*(parts+2), NULL, pkt_usec);
		*pkt_usec *= 1000;
		*pkt_time = mktime(&tm);

		g_strfreev(parts);
		return CISCODUMP_PARSER_IN_HEADER;
	}
	g_strfreev(parts);

	/* we got a line of the packet                                                          */
	/* A line looks like                                                                    */
	/* <address>: <1st group> <2nd group> <3rd group> <4th group> <ascii representation>    */
	/* ABCDEF01: 01020304 05060708 090A0B0C 0D0E0F10 ................                       */
	/* Note that any of the 4 groups are optional and that a group can be 1 to 4 bytes long */
	parts = g_regex_split_simple(
		"^[\\dA-F]{8,8}:\\s+([\\dA-F]{2,8})\\s+([\\dA-F]{2,8}){0,1}\\s+([\\dA-F]{2,8}){0,1}\\s+([\\dA-F]{2,8}){0,1}.*",
		line, G_REGEX_CASELESS, 0);

	part = parts;
	if (*part && *(part+1)) {
		/* There is at least one match. Skip first string */
		part++;
		while(*part) {
			/* RE matched */
			if (strlen(*part) > 1) {
				ws_hexstrtou32(*part, NULL, &value);
				value = g_ntohl(value);
				size = strlen(*part) / 2;
				memcpy(packet + *offset, &value, size);
				*offset += (guint32)size;
			}
			part++;
		}
	}
	g_strfreev(parts);
	return CISCODUMP_PARSER_IN_PACKET;
}

static int parse_line_ios_xe(guint8* packet, unsigned* offset, char* line)
{
	char** parts;
	char** part;
	guint32 value;
	size_t size;

	if (strlen(line) <= 1) {
		return CISCODUMP_PARSER_END_PACKET;
	}

	/*
0
  0000:  00000C07 AC154C5D 3C259068 08004500   ......L]<%.h..E.
  0010:  00547549 40003F01 B582C0A8 4983C0A8   .TuI@.?.....I...
  0020:  46090800 B28E456E 00030000 00000000   F.....En........
  0030:  00000000 00000000 00000000 00000000   ................
  0040:  00000000 00000000 00000000 00000000   ................
  0050:  00000000 00000000 00000000 00000000   ................
  0060:  0000                                  ..

1
  0000:  4C5D3C25 9068A49B CD904C74 08004500   L]<%.h....Lt..E.
  0010:  00547549 4000FF01 F581C0A8 4609C0A8   .TuI@.......F...
  0020:  49830000 BA8E456E 00030000 00000000   I.....En........
  0030:  00000000 00000000 00000000 00000000   ................
  0040:  00000000 00000000 00000000 00000000   ................
  0050:  00000000 00000000 00000000 00000000   ................
  0060:  0000                                  ..
*/

	/* we got the packet header                                    */
	/*0*/
	if (g_regex_match_simple("^\\d+$", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)) {
		return CISCODUMP_PARSER_IN_HEADER;
	}

	/* we got a line of the packet                                                          */
	/* A line looks like                                                                    */
	/*   0000:  00000C07 AC154C5D 3C259068 08004500   ......L]<%.h..E.                      */
	/*   ...                                                                                */
	/*   0060:  0000                                  ..                                    */
	/* Note that any of the 4 groups are optional and that a group can be 1 to 8 bytes long */
	parts = g_regex_split_simple(
		"^\\s+[0-9A-F]{4,4}:  ([0-9A-F]{2,8}) ([0-9A-F]{2,8}){0,1} ([0-9A-F]{2,8}){0,1} ([0-9A-F]{2,8}){0,1}\\s+.*",
		line, G_REGEX_CASELESS, 0);

	part = parts;
	if (*part && *(part+1)) {
		/* There is at least one match. Skip first string */
		part++;
		while(*part) {
			if (strlen(*part) > 1) {
				ws_hexstrtou32(*part, NULL, &value);
				value = g_ntohl(value);
				size = strlen(*part) / 2;
				memcpy(packet + *offset, &value, size);
				*offset += (guint32)size;
			}
			part++;
		}
	}
	g_strfreev(parts);

	return CISCODUMP_PARSER_IN_PACKET;
}

static int parse_line_asa(guint8* packet, unsigned* offset, char* line, guint32 *current_max, time_t *pkt_time, guint32 *pkt_usec)
{
	char** parts;
	char** part;
	guint16 value;
	size_t size;
	guint32 new_max;

	if (strlen(line) <= 1) {
		return CISCODUMP_PARSER_UNKNOWN;
	}

	/*
4599 packets captured

   1: 20:40:01.108469       10.124.255.212 > 10.124.255.5 icmp: echo request
0x0000 a453 0ef3 7fc0 74ad 98e5 0004 0800 4500 .S....t.......E.
0x0010 0054 dc73 4000 4001 4a63 0a7c ffd4 0a7c .T.s@.@.Jc.|...|
0x0020 ff05 0800 275b d0a4 0000 0000 0000 0000 ....'[..........
0x0030 0000 0000 0000 0000 0000 0000 0000 0000 ................
0x0040 0000 0000 0000 0000 0000 0000 0000 0000 ................
0x0050 0000 0000 0000 0000 0000 0000 0000 0000 ................
0x0060 0000                                    ..
1 packet shown
*/

	/* Update count of available packets */
	/* 4599 packets captured */
	packets_captured_count_asa(line, &new_max, NULL);
	if (new_max > 0) {
		*current_max = new_max;
		return CISCODUMP_PARSER_IN_HEADER;
	}

	/* we got the packet header                                    */
	/*   1: 20:40:01.108469       10.124.255.212 > 10.124.255.5 icmp: echo request */
	parts = g_regex_split_simple("^\\s*\\d+:\\s+(\\d+):(\\d+):(\\d+)\\.(\\d+)\\s+", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0);
	if (parts && *(parts+1)) {
		/* RE matched */
		struct tm *tm;
		time_t t;

		t = time(0);
		tm = localtime(&t);
		ws_strtoi32(*(parts+1), NULL, &(tm->tm_hour));
		ws_strtoi32(*(parts+2), NULL, &(tm->tm_min));
		ws_strtoi32(*(parts+3), NULL, &(tm->tm_sec));
		ws_strtou32(*(parts+4), NULL, pkt_usec);
		*pkt_time = mktime(tm);

		g_strfreev(parts);
		return CISCODUMP_PARSER_IN_HEADER;
	}
	g_strfreev(parts);

	/* we got the packet tail */
	/* 1 packet shown         */
	if (g_regex_match_simple("^\\s*1 packet shown.*$", line, (GRegexCompileFlags) (G_REGEX_CASELESS | G_REGEX_RAW), 0)) {
		return CISCODUMP_PARSER_END_PACKET;
	}

	/* we got a line of the packet                                                          */
	/* A line looks like                                                                    */
	/* 0x<address>: <1st group> <...> <8th group> <5th group> <ascii representation>        */
	/* 0x0000 a453 0ef3 7fc0 74ad 98e5 0004 0800 4500 -.S....t.......E.                     */
	/* 0x0060 0000                                    ..                                    */
	/* Note that any of the 8 groups are optional and that a group can be 1 to 8 bytes long */
	parts = g_regex_split_simple(
		"^0x[0-9A-F]{4,4}\\s+([0-9A-F]{2,4}) ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1} ([0-9A-F]{2,4}){0,1}\\s+.*",
		line, G_REGEX_CASELESS, 0);

	part = parts;
	if (*part && *(part+1)) {
		/* There is at least one match. Skip first string */
		part++;
		while(*part) {
			if (strlen(*part) > 1) {
				ws_hexstrtou16(*part, NULL, &value);
				value = g_ntohs(value);
				size = strlen(*part) / 2;
				memcpy(packet + *offset, &value, size);
				*offset += (guint32)size;
			}
			part++;
		}
	}
	g_strfreev(parts);

	return CISCODUMP_PARSER_IN_PACKET;
}

/* IOS: Reads response and parses buffer till prompt received */
static int process_buffer_response_ios(ssh_channel channel, guint8* packet, FILE* fp, const guint32 count, guint32 *processed_packets)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 read_packets = 1;
	int status = CISCODUMP_PARSER_STARTING;
	int loop_end = 0;
	unsigned packet_size = 0;
	time_t pkt_time = 0;
	guint32 pkt_usec = 0;
	guint32 len = 0;

	/* Process response */
	do {

		loop_end = 0;
		/* Read input till EOLN or prompt */
		switch (ssh_channel_read_prompt(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
			case READ_PROMPT_EOLN:
				status = parse_line_ios(packet, &packet_size, line, status, &pkt_time, &pkt_usec);

				if (status == CISCODUMP_PARSER_END_PACKET) {
					ws_debug("Read packet %d\n", read_packets);
					if (read_packets > *processed_packets) {
						int err;
						guint64 bytes_written;

						ws_debug("Exporting packet %d\n", *processed_packets);
						/*  dump the packet to the pcap file */
						if (!libpcap_write_packet(fp,
								pkt_time, pkt_usec,
								packet_size, packet_size, packet, &bytes_written, &err)) {
							ws_debug("Error in libpcap_write_packet(): %s", g_strerror(err));
							break;
						}
						fflush(fp);
						ws_debug("Dumped packet %u size: %u\n", *processed_packets, packet_size);
						(*processed_packets)++;
					}
					packet_size = 0;
					read_packets++;
				}
				break;
			case READ_PROMPT_PROMPT:
				ws_debug("Prompt found");
				loop_end = 1;
				break;
			default:
				/* We do not have better solution for that cases */
				ws_warning("Timeout or response was too long\n");
				return FALSE;
		}
		len = 0;
		ws_debug("loop end detection %d %d %d %d", end_application, loop_end, *processed_packets, count);
	} while ((!end_application) && (!loop_end) && (*processed_packets < count));

	return TRUE;
}

/* IOS: Queries buffer content and reads it */
static void ssh_loop_read_ios(ssh_channel channel, FILE* fp, const guint32 count)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint8* packet;
	guint32 processed_packets = 0;
	gboolean running = TRUE;
	guint32 current_max = 0;
	guint32 new_max;

	/* This is big enough to put on the heap */
	packet = (guint8*)g_malloc(PACKET_MAX_SIZE);

	do {
		guint32 len = 0;

		/* Query count of available packets in buffer */
		if (ssh_channel_printf(channel, "show monitor capture buffer %s parameters\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE) {
			g_free(packet);
			return;
		}
		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			g_free(packet);
			return;
		}
		ws_debug("Read: %s", line);
		packets_captured_count_ios(line, &new_max, &running);
		ws_debug("Max counts %d %d", current_max, new_max);
		if (new_max == current_max) {
			/* There is no change in count of available packets, repeat the loop */
			continue;
		} else if (new_max < current_max) {
			/* Buffer was cleared, stop */
			g_free(packet);
			return;
		}
		current_max = new_max;
		ws_debug("New packet count %d\n", current_max);

		/* Dump buffer */
		if (ssh_channel_printf(channel, "show monitor capture buffer %s dump\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE) {
			g_free(packet);
			return;
		}

		/* Process buffer */
		if (!process_buffer_response_ios(channel, packet, fp, count, &processed_packets)) {
			g_free(packet);
			return;
		}
	} while (!end_application && running && (processed_packets < count));

	g_free(packet);

	/* Discard any subsequent messages */
	read_output_bytes_any(channel, -1, NULL);
}

/* IOS-XE: Reads response and parses buffer till prompt received */
static int process_buffer_response_ios_xe(ssh_channel channel, guint8* packet, FILE* fp, const guint32 count, guint32 *processed_packets)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 read_packets = 1;
	int status = CISCODUMP_PARSER_STARTING;
	int loop_end = 0;
	unsigned packet_size = 0;
	guint32 len = 0;

	/* Process response */
	do {
		loop_end = 0;
		/* Read input till EOLN or prompt */
		switch (ssh_channel_read_prompt(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
			case READ_PROMPT_EOLN:
				status = parse_line_ios_xe(packet, &packet_size, line);

				if (status == CISCODUMP_PARSER_END_PACKET) {
					ws_debug("Read packet %d\n", read_packets);
					if (read_packets > *processed_packets) {
						int err;
						gint64 cur_time = g_get_real_time();
						guint64 bytes_written;

						ws_debug("Exporting packet %d\n", *processed_packets);
						/*  dump the packet to the pcap file */
						if (!libpcap_write_packet(fp,
								(guint32)(cur_time / G_USEC_PER_SEC), (guint32)(cur_time % G_USEC_PER_SEC),
								packet_size, packet_size, packet, &bytes_written, &err)) {
							ws_debug("Error in libpcap_write_packet(): %s", g_strerror(err));
							break;
						}
						fflush(fp);
						ws_debug("Dumped packet %u size: %u\n", *processed_packets, packet_size);
						(*processed_packets)++;
					}
					packet_size = 0;
					read_packets++;
				}
				break;
			case READ_PROMPT_PROMPT:
				ws_debug("Prompt found");
				loop_end = 1;
				break;
			default:
				/* We do not have better solution for that cases */
				ws_warning("Timeout or response was too long\n");
				return FALSE;
		}
		len = 0;
		ws_debug("loop end detection %d %d %d %d", end_application, loop_end, *processed_packets, count);
	} while ((!end_application) && (!loop_end) && (*processed_packets < count));

	return TRUE;
}

/* IOS-XE: Queries buffer content and reads it */
static void ssh_loop_read_ios_xe(ssh_channel channel, FILE* fp, const guint32 count)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint8* packet;
	guint32 processed_packets = 0;
	gboolean running = TRUE;
	guint32 current_max = 0;
	guint32 new_max;

	/* This is big enough to put on the heap */
	packet = (guint8*)g_malloc(PACKET_MAX_SIZE);

	do {
		guint32 len = 0;

		/* Query count of available packets in buffer */
		if (ssh_channel_printf(channel, "show monitor capture %s buffer | inc packets in buf\nshow monitor capture %s | inc Status :\n", WIRESHARK_CAPTURE, WIRESHARK_CAPTURE) == EXIT_FAILURE) {
			g_free(packet);
			return;
		}
		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			g_free(packet);
			return;
		}
		ws_debug("Read: %s", line);
		packets_captured_count_ios_xe(line, &new_max, &running);
		ws_debug("Max counts %d %d", current_max, new_max);
		if (new_max == current_max) {
			/* There is no change in count of available packets, repeat the loop */
			continue;
		} else if (new_max < current_max) {
			/* Buffer was cleared, stop */
			g_free(packet);
			return;
		}
		current_max = new_max;
		ws_debug("New packet count %d\n", current_max);

		/* Dump buffer */
		if (ssh_channel_printf(channel, "show monitor capture %s buffer dump\n", WIRESHARK_CAPTURE) == EXIT_FAILURE) {
			g_free(packet);
			return;
		}

		/* Process buffer */
		if (!process_buffer_response_ios_xe(channel, packet, fp, count, &processed_packets)) {
			g_free(packet);
			return;
		}
	} while (!end_application && running && (processed_packets < count));

	g_free(packet);

	/* Discard any subsequent messages */
	read_output_bytes_any(channel, -1, NULL);
}

/* ASA: Reads response and parses buffer till prompt end of packet received */
static int process_buffer_response_asa(ssh_channel channel, guint8* packet, FILE* fp, const guint32 count, guint32 *processed_packets, guint32 *current_max)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 read_packets = 1;
	int status = CISCODUMP_PARSER_STARTING;
	int loop_end = 0;
	unsigned packet_size = 0;

	do {
		time_t pkt_time = 0;
		guint32 pkt_usec = 0;
		guint32 len = 0;

		/* Dump buffer */
		if (ssh_channel_printf(channel, "show cap %s packet-number %ld dump\n", WIRESHARK_CAPTURE, (*processed_packets)+1) == EXIT_FAILURE) {
			return FALSE;
		}

		/* Process response */
		do {
			loop_end = 0;
			/* Read input till EOLN or prompt */
			switch (ssh_channel_read_prompt(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
				case READ_PROMPT_EOLN:
					status = parse_line_asa(packet, &packet_size, line, current_max, &pkt_time, &pkt_usec);

					if (status == CISCODUMP_PARSER_END_PACKET) {
						ws_debug("Read packet %d\n", read_packets);
						int err;
						guint64 bytes_written;

						ws_debug("Exporting packet %d\n", *processed_packets);
						/*  dump the packet to the pcap file */
						if (!libpcap_write_packet(fp,
								pkt_time, pkt_usec,
								packet_size, packet_size, packet, &bytes_written, &err)) {
							ws_debug("Error in libpcap_write_packet(): %s", g_strerror(err));
							break;
						}
						fflush(fp);
						ws_debug("Dumped packet %u size: %u\n", *processed_packets, packet_size);
						(*processed_packets)++;
						packet_size = 0;
						read_packets++;
						loop_end = 1;
					}
					break;
				case READ_PROMPT_PROMPT:
					ws_debug("Prompt found");
					loop_end = 1;
					break;
				default:
					/* We do not have better solution for that cases */
					ws_warning("Timeout or response was too long\n");
					return FALSE;
			}
			len = 0;
			ws_debug("loop end detection1 %d %d", *processed_packets, count);
		} while (!end_application && !loop_end);
		ws_debug("loop end detection2 %d %d %d", end_application, *processed_packets, count);
	} while (!end_application && (*processed_packets < *current_max) && ((*processed_packets < count)));

	return TRUE;
}

/* ASA: Queries buffer content and reads it */
static void ssh_loop_read_asa(ssh_channel channel, FILE* fp, const guint32 count)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint8* packet;
	guint32 processed_packets = 0;
	guint32 current_max = 0;
	gboolean running = TRUE;
	guint32 new_max;

	/* This is big enough to put on the heap */
	packet = (guint8*)g_malloc(PACKET_MAX_SIZE);

	do {
		guint32 len = 0;

		/* Query count of available packets in buffer */
		if (ssh_channel_printf(channel, "show cap %s packet-number 0 | inc packets captured\nshow cap | inc %s\n", WIRESHARK_CAPTURE, WIRESHARK_CAPTURE) == EXIT_FAILURE) {
			g_free(packet);
			return;
		}
		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			g_free(packet);
			return;
		}
		ws_debug("Read: %s", line);
		packets_captured_count_asa(line, &new_max, &running);
		ws_debug("Max counts %d %d", current_max, new_max);
		if (new_max == current_max) {
			/* There is no change in count of available packets, repeat the loop */
			continue;
		} else if (new_max < current_max) {
			/* Buffer was cleared, stop */
			g_free(packet);
			return;
		}
		current_max = new_max;
		ws_debug("New packet count %d\n", current_max);

		/* Process buffer */
		if (!process_buffer_response_asa(channel, packet, fp, count, &processed_packets, &current_max)) {
			g_free(packet);
			return;
		}
	} while (!end_application && running && (processed_packets < count));

	g_free(packet);

	/* Discard any subsequent messages */
	read_output_bytes_any(channel, -1, NULL);
}


static void ssh_loop_read(ssh_channel channel, FILE* fp, const guint32 count _U_, CISCO_SW_TYPE sw_type)
{
	ws_debug("Starting reading loop");
	switch (sw_type) {
		case CISCO_IOS:
			ssh_loop_read_ios(channel, fp, count);
			break;
		case CISCO_IOS_XE:
			ssh_loop_read_ios_xe(channel, fp, count);
			break;
		case CISCO_ASA:
			ssh_loop_read_asa(channel, fp, count);
			break;
		case CISCO_UNKNOWN:
			break;
	}
	ws_debug("Reading loop finished");
}

static int detect_host_prompt(ssh_channel channel)
{
	char line[SSH_READ_BLOCK_SIZE + 1];
	int len = 0;
	char prompt_2[SSH_READ_BLOCK_SIZE + 1];

	/* Discard any login message */
	if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
		return EXIT_FAILURE;

	if (ssh_channel_printf(channel, "\n") == EXIT_FAILURE)
		return EXIT_FAILURE;

	/* Check if there is any response to empty line */
	switch (ssh_channel_read_line_timeout(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
		case READ_LINE_EOLN:
			break;
		default:
			return EXIT_FAILURE;
	}

	if (ssh_channel_printf(channel, "\n") == EXIT_FAILURE)
		return EXIT_FAILURE;

	/* Read prompt_str and level char */
	switch (ssh_channel_read_line_timeout(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
		case READ_LINE_EOLN:
			break;
		default:
			return EXIT_FAILURE;
	}
	if (len > 0) {
		g_strlcpy(prompt_str, line, SSH_READ_BLOCK_SIZE + 1);

		/* Is there hashtag at the end => enabled mode? */
		if (prompt_str[strlen(prompt_str)-1] != '#') {
			/* Is there hashtag and space (ASA) at the end => enabled mode? */
			if ((prompt_str[strlen(prompt_str)-2] != '#') || (prompt_str[strlen(prompt_str)-1] != ' ')) {
				return EXIT_FAILURE;
			}
		}
		prompt_len = (gint32)strlen(prompt_str);
	} else {
		return EXIT_FAILURE;
        }

	if (ssh_channel_printf(channel, "\n") == EXIT_FAILURE)
		return EXIT_FAILURE;

	/* Read prompt_str and level char again */
	switch (ssh_channel_read_line_timeout(channel, line, &len, SSH_READ_BLOCK_SIZE)) {
		case READ_LINE_EOLN:
			break;
		default:
			return EXIT_FAILURE;
	}
	if (len > 0) {
		g_strlcpy(prompt_2, line, SSH_READ_BLOCK_SIZE + 1);
		/* Does second prompt_str match first one? */
		if (0 == g_strcmp0(prompt_str, prompt_2)) {
			ws_debug("Detected prompt %s", prompt_str);
			return TRUE;
		}
	}

	return EXIT_FAILURE;
}

static int check_ios_version(ssh_channel channel, CISCO_SW_TYPE *sw_type)
{
	gchar* cmdline_version = "show version | include Version\n";
	const gchar* msg_ios = "Cisco IOS Software";
	const gchar* msg_ios_xe = "Cisco IOS XE Software";
	const gchar* msg_asa = "Cisco Adaptive Security Appliance Software";
	const gchar* msg_version = "Version ";
	gchar version[255];
	gint sw_major = 0;
	gint sw_minor = 0;
	gchar* cur;

	memset(version, 0x0, 255);

	/* Discard any login message */
	if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
		return FALSE;

	if (ssh_channel_write(channel, cmdline_version, (guint32)strlen(cmdline_version)) == SSH_ERROR)
		return FALSE;
	if (read_output_bytes(channel, 255, version) == EXIT_FAILURE)
		return FALSE;

	/* Discard any subsequent text */
	if (read_output_bytes(channel, -1, NULL) == EXIT_FAILURE)
		return FALSE;

	/* We should check IOS XE first as its version contains IOS string too */
	cur = g_strstr_len(version, strlen(version), msg_ios_xe);
	if (cur) {
		*sw_type = CISCO_IOS_XE;
		cur += strlen(msg_ios_xe);
	} else {
		cur = g_strstr_len(version, strlen(version), msg_ios);
		if (cur) {
			*sw_type = CISCO_IOS;
			cur += strlen(msg_ios);
		} else {
			cur = g_strstr_len(version, strlen(version), msg_asa);
			if (cur) {
				*sw_type = CISCO_ASA;
			cur += strlen(msg_asa);
			}
		}
	}

	if (*sw_type != CISCO_UNKNOWN) {
		cur = g_strstr_len(cur, 255-strlen(cur), msg_version);
		if (cur) {
			cur += strlen(msg_version);
			if (sscanf(cur, "%u.%u", &sw_major, &sw_minor) != 2)
				return FALSE;

			switch (*sw_type) {
				case CISCO_IOS:
					ws_debug("Current IOS version: %u.%u", sw_major, sw_minor);
					if ((sw_major > MINIMUM_IOS_MAJOR) || (sw_major == MINIMUM_IOS_MAJOR && sw_minor >= MINIMUM_IOS_MINOR)) {
						return TRUE;
					}
					break;
				case CISCO_IOS_XE:
					ws_debug("Current IOS XE version: %u.%u", sw_major, sw_minor);
					if ((sw_major > MINIMUM_IOS_XE_MAJOR) || (sw_major == MINIMUM_IOS_XE_MAJOR && sw_minor >= MINIMUM_IOS_XE_MINOR)) {
						return TRUE;
					}
					break;
				case CISCO_ASA:
					ws_debug("Current ASA version: %u.%u", sw_major, sw_minor);
					if ((sw_major > MINIMUM_ASA_MAJOR) || (sw_major == MINIMUM_ASA_MAJOR && sw_minor >= MINIMUM_ASA_MINOR)) {
						return TRUE;
					}
					break;
				default:
					return FALSE;
			}
			ws_warning("Recognized software type, but minimal version requirements were not met\n");
			return FALSE;
		} else {
			ws_warning("Recognized software type %d, but unrecognized version\n", *sw_type);
		}
	} else {
		ws_warning("Unrecognized type of control software.");
	}

	return FALSE;
}

static gboolean run_capture_ios(ssh_channel channel, const char* iface, const char* cfilter, const guint32 count)
{
	char* cmdline = NULL;
	int ret = 0;
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 len;
	gchar* iface_copy = g_strdup(iface);
	gchar* iface_one;
	gchar* str = NULL;
	int wscp_cnt = 1;
	gchar* wscp_str = NULL;

	if (ssh_channel_printf(channel, "terminal length 0\n") == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	if (ssh_channel_printf(channel, "monitor capture buffer %s max-size 9500\n", WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	if (count > 0) {
		if (ssh_channel_printf(channel, "monitor capture buffer %s limit packet-count %u\n", WIRESHARK_CAPTURE_BUFFER, count) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}
        }

	if (cfilter) {
		gchar* multiline_filter;
		gchar* chr;

		if (ssh_channel_printf(channel, "configure terminal\n") == EXIT_FAILURE)
			goto error;

		if (ssh_channel_printf(channel, "ip access-list extended %s\n", WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;

		multiline_filter = g_strdup(cfilter);
		chr = multiline_filter;
		while((chr = g_strstr_len(chr, strlen(chr), ",")) != NULL) {
			chr[0] = '\n';
			ws_debug("Splitting filter into multiline");
		}
		ret = ssh_channel_write(channel, multiline_filter, (uint32_t)strlen(multiline_filter));
		g_free(multiline_filter);
		if (ret == SSH_ERROR)
			goto error;

		if (ssh_channel_printf(channel, "\nend\n") == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		if (ssh_channel_printf(channel, "monitor capture buffer %s filter access-list %s\n",
				WIRESHARK_CAPTURE_BUFFER, WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}
	}

	wscp_cnt = 1;
	for (str = iface_copy; ; str = NULL) {
		iface_one = strtok(str, ",");
		if (iface_one == NULL)
			break;

		wscp_str = g_strdup_printf("%s_%d", WIRESHARK_CAPTURE_POINT, wscp_cnt);
		wscp_cnt++;

		if (0 == g_strcmp0(iface_one, "process-switched")) {
			cmdline = g_strdup_printf("monitor capture point ip process-switched %s both", wscp_str);
		} else if (0 == g_strcmp0(iface_one, "from-us")) {
			cmdline = g_strdup_printf("monitor capture point ip process-switched %s from-us", wscp_str);
		} else {
			cmdline = g_strdup_printf("monitor capture point ip cef %s %s both", wscp_str, iface_one);
		}

		if (ssh_channel_printf(channel, "%s\n", cmdline) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		if (ssh_channel_printf(channel, "monitor capture point associate %s %s \n", wscp_str,
				WIRESHARK_CAPTURE_BUFFER) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		g_free(cmdline);
		cmdline = NULL;
	}

	wscp_cnt = 1;
	for (str = iface_copy; ; str = NULL) {
		iface_one = strtok(str, ",");
		if (iface_one == NULL)
			break;

		wscp_str = g_strdup_printf("%s_%d", WIRESHARK_CAPTURE_POINT, wscp_cnt);
		wscp_cnt++;

		if (ssh_channel_printf(channel, "monitor capture point start %s\n", wscp_str) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		g_free(wscp_str);
		wscp_str = NULL;
	}

	g_free(iface_copy);
	return TRUE;
error:
	g_free(wscp_str);
	g_free(iface_copy);
	g_free(cmdline);
	ws_warning("Error running ssh remote command");

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return FALSE;
}

static gboolean run_capture_ios_xe(ssh_channel channel, const char* iface, const char* cfilter, const guint32 count)
{
	int ret = 0;
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 len;
	gchar* iface_copy = g_strdup(iface);
	gchar* iface_one;
	gchar* str = NULL;

	if (ssh_channel_printf(channel, "terminal length 0\n") == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	if (ssh_channel_printf(channel, "monitor capture %s limit packet-len 9500\n", WIRESHARK_CAPTURE) == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	if (count > 0) {
		if (ssh_channel_printf(channel, "monitor capture %s limit packets %u\n", WIRESHARK_CAPTURE, count) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}
	}

	if (cfilter) {
		gchar* multiline_filter;
		gchar* chr;

		if (ssh_channel_printf(channel, "configure terminal\n") == EXIT_FAILURE)
			goto error;

		if (ssh_channel_printf(channel, "ip access-list extended %s\n", WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;

		multiline_filter = g_strdup(cfilter);
		chr = multiline_filter;
		while((chr = g_strstr_len(chr, strlen(chr), ",")) != NULL) {
			chr[0] = '\n';
			ws_debug("Splitting filter into multiline");
		}
		ret = ssh_channel_write(channel, multiline_filter, (uint32_t)strlen(multiline_filter));
		g_free(multiline_filter);
		if (ret == SSH_ERROR)
			goto error;

		if (ssh_channel_printf(channel, "\nend\n") == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		if (ssh_channel_printf(channel, "monitor capture %s access-list %s\n",
				WIRESHARK_CAPTURE, WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;
	} else {
		if (ssh_channel_printf(channel, "monitor capture %s match any\n",
				WIRESHARK_CAPTURE) == EXIT_FAILURE)
			goto error;
	}

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	for (str = iface_copy; ; str = NULL) {
		iface_one = strtok(str, ",");
		if (iface_one == NULL)
			break;

		if (0 == g_strcmp0(iface_one, "control-plane")) {
			if (ssh_channel_printf(channel, "monitor capture %s control-plane both\n", WIRESHARK_CAPTURE
					) == EXIT_FAILURE)
				goto error;
		} else {
			if (ssh_channel_printf(channel, "monitor capture %s interface %s both\n", WIRESHARK_CAPTURE,
					iface_one) == EXIT_FAILURE)
				goto error;
		}
	}

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	if (ssh_channel_printf(channel, "monitor capture %s start\n", WIRESHARK_CAPTURE) == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE,
	    "(Capture is not Supported|Unable to activate Capture)")
	   ) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	g_free(iface_copy);
	return TRUE;
error:
	g_free(iface_copy);
	ws_warning("Error running ssh remote command");

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return FALSE;
}

static gboolean run_capture_asa(ssh_channel channel, const char* iface, const char* cfilter)
{
	char* cmdline = NULL;
	char line[SSH_READ_BLOCK_SIZE + 1];
	guint32 len;
	gchar *sep;
	gboolean process_filter = TRUE;
	gchar* iface_copy = g_strdup(iface);
	gchar* iface_one;
	gchar* str = NULL;

	if (ssh_channel_printf(channel, "terminal pager 0\n") == EXIT_FAILURE)
		goto error;

	if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
		ws_warning("Received response: %s", crtoln(line));
		goto error;
	}

	for (str = iface_copy; ; str = NULL) {
		iface_one = strtok(str, ",");
		if (iface_one == NULL)
			break;

		if (0 == g_strcmp0(iface_one, "asp-drop")) {
			/* asp-drop: asp-drop: capture %s type asp-drop all packet-length 9216 !INCLUDE-DECRYPTED
			 */
			cmdline = g_strdup_printf("capture %s type asp-drop all packet-length 9216", WIRESHARK_CAPTURE);
		} else if (NULL != (sep = g_strstr_len(iface_one, -1, "---"))) {
			/* Interface type separator found. We support:
			 * isakmp---ifname: capture %s type isakmp packet-length 32810 interface %s
			 * // webvpn---ifname: capture %s type webvpn user %s !NO FILTER !INCLUDE-DECRYPTED
			 * lacp---ifname: capture %s type lacp interface %s packet-length 9216 !NO FILTER !INCLUDE-DECRYPTED
			 * tls-proxy---ifname: capture %s type tls-proxy packet-length 9216 interface %s
			 * inline-tag---ifname: capture %s type inline-tag packet-length 9216 interface %s
			 * raw-data---ifname: capture %s type rawdata packet-length 9216 interface %s
			 *
			 * We support /decrypted for some of it:
			 * isakmp/decrypted---ifname
			 * tls-proxy/decrypted---ifname
			 * inline-tag/decrypted---ifname
			 * raw-data/decrypted---ifname
			 */
			gchar* ifname = sep+3;

			if (strstr(iface_one,  "isakmp")) {
				if (strstr(iface_one,  "/decrypted")) {
					cmdline = g_strdup_printf("capture %s type isakmp include-decrypted packet-length 32810 interface %s", WIRESHARK_CAPTURE, ifname);
				} else {
					cmdline = g_strdup_printf("capture %s type isakmp packet-length 32810 interface %s", WIRESHARK_CAPTURE, ifname);
				}
				/* Completelly different output
				} else if (strstr(iface_one,  "webvpn")) {
					cmdline = g_strdup_printf("capture %s type webvpn user %s", WIRESHARK_CAPTURE, ifname);
					process_filter = FALSE;
				*/
			} else if (strstr(iface_one,  "lacp")) {
				cmdline = g_strdup_printf("capture %s type lacp interface %s packet-length 9216", WIRESHARK_CAPTURE, ifname);
				process_filter = FALSE;
			} else if (strstr(iface_one,  "tls-proxy")) {
				if (strstr(iface_one,  "/decrypted")) {
					cmdline = g_strdup_printf("capture %s type tls-proxy include-decrypted packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				} else {
					cmdline = g_strdup_printf("capture %s type tls-proxy packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				}
			} else if (strstr(iface_one,  "inline-tag")) {
				if (strstr(iface_one,  "/decrypted")) {
					cmdline = g_strdup_printf("capture %s type inline-tag include-decrypted packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				} else {
					cmdline = g_strdup_printf("capture %s type inline-tag packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				}
			} else if (strstr(iface_one,  "raw-data")) {
				if (strstr(iface_one,  "/decrypted")) {
					cmdline = g_strdup_printf("capture %s type raw-data include-decrypted packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				} else {
					cmdline = g_strdup_printf("capture %s type raw-data packet-length 9216 interface %s", WIRESHARK_CAPTURE, ifname);
				}
			} else {
				ws_warning("Unknown interface type : %s", iface_one);
				goto error;
			}
		} else {
			/* Just interface name */
			cmdline = g_strdup_printf("capture %s type raw-data packet-length 9216 interface %s", WIRESHARK_CAPTURE, iface_one);
		}

		if (ssh_channel_printf(channel, "%s\n", cmdline) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		g_free(cmdline);
		cmdline = NULL;
	}

	if (process_filter && cfilter) {
		gchar* multiline_filter;
		gchar* chr;
		gchar* start;

		if (ssh_channel_printf(channel, "configure terminal\n") == EXIT_FAILURE)
			goto error;

		multiline_filter = g_strdup(cfilter);
		chr = multiline_filter;
		start = multiline_filter;
		while((chr = g_strstr_len(start, strlen(start), ",")) != NULL) {
			chr[0] = '\0';
			ws_debug("Splitting filter into multiline");
			if (ssh_channel_printf(channel, "access-list %s %s\n", WIRESHARK_CAPTURE_ACCESSLIST, start) == EXIT_FAILURE)
				goto error;
			start = chr+1;
		}

		if (ssh_channel_printf(channel, "access-list %s %s\n", WIRESHARK_CAPTURE_ACCESSLIST, start) == EXIT_FAILURE)
			goto error;

		if (ssh_channel_printf(channel, "\nend\n") == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}

		if (ssh_channel_printf(channel, "capture %s access-list %s\n", WIRESHARK_CAPTURE, WIRESHARK_CAPTURE_ACCESSLIST) == EXIT_FAILURE)
			goto error;

		if (!ssh_channel_wait_prompt_check_error(channel, line, &len, SSH_READ_BLOCK_SIZE, NULL)) {
			ws_warning("Received response: %s", crtoln(line));
			goto error;
		}
	}

	g_free(iface_copy);
	return TRUE;
error:
	g_free(iface_copy);
	g_free(cmdline);
	ws_warning("Error running ssh remote command");

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return FALSE;
}

static ssh_channel open_channel(ssh_session sshs)
{
	ssh_channel channel;

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

	return channel;

error:
	ws_warning("Error running ssh remote command");

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return NULL;
}

static gboolean run_capture(ssh_channel channel, const char* iface, const char* cfilter, const guint32 count, CISCO_SW_TYPE *sw_type)
{
	if (!detect_host_prompt(channel))
		goto error;

	if (!check_ios_version(channel, sw_type))
		goto error;

	switch (*sw_type) {
		case CISCO_IOS:
			return run_capture_ios(channel, iface, cfilter, count);
		case CISCO_IOS_XE:
			return run_capture_ios_xe(channel, iface, cfilter, count);
		case CISCO_ASA:
			return run_capture_asa(channel, iface, cfilter);
		case CISCO_UNKNOWN:
			ws_warning("Unsupported cisco software. It will not collect any data most probably!");
			return FALSE;
	}

error:
	ws_warning("Error running ssh remote command");

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return FALSE;
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
	CISCO_SW_TYPE sw_type = CISCO_UNKNOWN;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fp = fopen(fifo, "wb");
		if (!fp) {
			ws_warning("Error creating output file: %s", g_strerror(errno));
			return EXIT_FAILURE;
		}
	}

#ifdef _WIN32
	if (!SetConsoleCtrlHandler(exit_from_loop, TRUE)) {
		ws_warning("Can't set console handler");
		goto cleanup;
	}
#else
	/* Catch signals to be able to cleanup config later */
	if (signal(SIGINT, exit_from_loop) == SIG_ERR) {
		ws_warning("Can't set SIGINT signal handler");
		goto cleanup;
	}
	if (signal(SIGTERM, exit_from_loop) == SIG_ERR) {
		ws_warning("Can't set SIGTERM signal handler");
		goto cleanup;
	}
	if (signal(SIGPIPE, exit_from_loop) == SIG_ERR) {
		ws_warning("Can't set SIGPIPE signal handler");
		goto cleanup;
	}
#endif /* _WIN32 */

	if (!libpcap_write_file_header(fp, 1, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
		ws_warning("Can't write pcap file header");
		goto cleanup;
	}

	ws_debug("Create first ssh session");
	sshs = create_ssh_connection(ssh_params, &err_info);
	if (!sshs) {
		ws_warning("Error creating connection: %s", err_info);
		goto cleanup;
	}

	channel = open_channel(sshs);
	if (!channel) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (!run_capture(channel, iface, cfilter, count, &sw_type)) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* read from channel and write into fp */
	ssh_loop_read(channel, fp, count, sw_type);

	/* Read loop can be terminated by signal or QUIT command in
	 * mid of long "show" command and its reading can take really
	 * long time. So we terminate ssh session and then
	 * create new one to cleanup configuration
	 */
	ws_debug("Disconnect first ssh session");
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_cleanup(&sshs, &channel);

	ws_debug("Create second ssh session");
	sshs = create_ssh_connection(ssh_params, &err_info);
	if (!sshs) {
		ws_warning("Error creating connection: %s", err_info);
		goto cleanup;
	}

	channel = open_channel(sshs);
	if (!channel) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* clean up and exit */
	ciscodump_cleanup(channel, iface, cfilter, sw_type);

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_cleanup(&sshs, &channel);

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
		ws_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, CISCODUMP_EXTCAP_INTERFACE)) {
		ws_warning("interface must be %s", CISCODUMP_EXTCAP_INTERFACE);
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

	/* Initialize log handler early so we can have proper logging during startup. */
	extcap_log_init("ciscodump");

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	err_msg = configuration_init(argv[0], NULL);
	if (err_msg != NULL) {
		ws_warning("Can't get pathname of directory containing the extcap program: %s.",
			err_msg);
		g_free(err_msg);
	}

	help_url = data_file_url("ciscodump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], CISCODUMP_VERSION_MAJOR, CISCODUMP_VERSION_MINOR,
		CISCODUMP_VERSION_RELEASE, help_url);
	add_libssh_info(extcap_conf);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, CISCODUMP_EXTCAP_INTERFACE, "Cisco remote capture", 147, "Remote capture dependent DLT");

	help_header = ws_strdup_printf(
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
	extcap_help_add_option(extcap_conf, "--proxycommand <proxy command>", "the command to use as proxy for the ssh connection");
	extcap_help_add_option(extcap_conf, "--remote-interface <iface>", "the remote capture interface");
	extcap_help_add_option(extcap_conf, "--remote-filter <filter>", "a filter for remote capture "
		"(default: don't capture data for all interfaces IPs)");

	ws_opterr = 0;
	ws_optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	ws_log_set_level(LOG_LEVEL_DEBUG);
	while ((result = ws_getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {

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
			ssh_params->host = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_PORT:
			if (!ws_strtou16(ws_optarg, NULL, &ssh_params->port) || ssh_params->port == 0) {
				ws_warning("Invalid port: %s", ws_optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_USERNAME:
			g_free(ssh_params->username);
			ssh_params->username = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_PASSWORD:
			g_free(ssh_params->password);
			ssh_params->password = g_strdup(ws_optarg);
			memset(ws_optarg, 'X', strlen(ws_optarg));
			break;

		case OPT_SSHKEY:
			g_free(ssh_params->sshkey_path);
			ssh_params->sshkey_path = g_strdup(ws_optarg);
			break;

		case OPT_SSHKEY_PASSPHRASE:
			g_free(ssh_params->sshkey_passphrase);
			ssh_params->sshkey_passphrase = g_strdup(ws_optarg);
			memset(ws_optarg, 'X', strlen(ws_optarg));
			break;

		case OPT_PROXYCOMMAND:
			g_free(ssh_params->proxycommand);
			ssh_params->proxycommand = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_INTERFACE:
			g_free(remote_interface);
			remote_interface = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_FILTER:
			g_free(remote_filter);
			remote_filter = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_COUNT:
			if (!ws_strtou32(ws_optarg, NULL, &count)) {
				ws_warning("Invalid packet count: %s", ws_optarg);
				goto end;
			}
			break;

		case ':':
			/* missing option argument */
			ws_warning("Option '%s' requires an argument", argv[ws_optind - 1]);
			break;

		default:
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg)) {
				ws_warning("Invalid option: %s", argv[ws_optind - 1]);
				goto end;
			}
		}
	}

	extcap_cmdline_debug(argv, argc);

	if (ws_optind != argc) {
		ws_warning("Unexpected extra option: %s", argv[ws_optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		unsigned int port;
		if (!ws_strtou16(ws_optarg, NULL, &ssh_params->port) || ssh_params->port == 0) {
			port = 22;
		} else {
			port = ssh_params->port;
		}
		ret = list_config(extcap_conf->interface, port);
		goto end;
	}

	err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		ws_warning("ERROR: %s", err_msg);
                g_free(err_msg);
		ws_warning("%s", please_report_bug());
		goto end;
	}

	if (extcap_conf->capture) {
		if (!ssh_params->host) {
			ws_warning("Missing parameter: --remote-host");
			goto end;
		}

		if (!remote_interface) {
			ws_warning("ERROR: No interface specified (--remote-interface)");
			goto end;
		}
		if (count == 0) {
			ws_warning("ERROR: count of packets must be specified (--remote-count)");
			goto end;
		}
		ssh_params->debug = extcap_conf->debug;
		ret = ssh_open_remote_connection(ssh_params, remote_interface,
			remote_filter, count, extcap_conf->fifo);
	} else {
		ws_debug("You should not come here... maybe some parameter missing?");
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
