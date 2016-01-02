/* randpktdump.c
 * randpktdump is an extcap tool used to generate random data for testing/educational purpose
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

#include "randpkt-core.h"

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

#ifdef HAVE_GETOPT_H
	#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
	#include "wsutil/wsgetopt.h"
#endif

#ifdef _WIN32
#include <io.h>
#endif

#if defined(_WIN32) && !defined(__CYGWIN__)
	#ifdef HAVE_WINDOWS_H
		#include <windows.h>
	#endif

	#include <ws2tcpip.h>

	#ifdef HAVE_WINSOCK2_H
		#include <winsock2.h>
	#endif

	#include <process.h>

	#define socket_handle_t SOCKET
#else
/*
 * UN*X, or Windows pretending to be UN*X with the aid of Cygwin.
 */
#define closesocket(socket)  close(socket)
#define socket_handle_t int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }
#define errmsprintf(...) { printf(__VA_ARGS__); printf("\n"); }

#define RANDPKT_EXTCAP_INTERFACE "randpkt"
#define RANDPKTDUMP_VERSION_MAJOR 0
#define RANDPKTDUMP_VERSION_MINOR 1
#define RANDPKTDUMP_VERSION_RELEASE 0

static gboolean verbose = TRUE;

enum {
	OPT_HELP = 1,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_LIST_INTERFACES,
	OPT_LIST_DLTS,
	OPT_INTERFACE,
	OPT_CONFIG,
	OPT_CAPTURE,
	OPT_CAPTURE_FILTER,
	OPT_FIFO,
	OPT_MAXBYTES,
	OPT_COUNT,
	OPT_RANDOM_TYPE,
	OPT_ALL_RANDOM,
	OPT_TYPE
};

static struct option longopts[] = {
	/* Generic application options */
	{ "help",					no_argument,      	NULL, OPT_HELP},
	{ "version",				no_argument,      	NULL, OPT_VERSION},
	{ "verbose",				optional_argument,	NULL, OPT_VERBOSE},
	/* Extcap options */
	{ "extcap-interfaces",		no_argument,      	NULL, OPT_LIST_INTERFACES},
	{ "extcap-dlts",			no_argument,      	NULL, OPT_LIST_DLTS},
	{ "extcap-interface",		required_argument,	NULL, OPT_INTERFACE},
	{ "extcap-config",			no_argument,      	NULL, OPT_CONFIG},
	{ "capture",				no_argument,      	NULL, OPT_CAPTURE},
	{ "extcap-capture-filter	",	required_argument,	NULL, OPT_CAPTURE_FILTER},
	{ "fifo",					required_argument,	NULL, OPT_FIFO},
	/* Interfaces options */
	{ "maxbytes",				required_argument,	NULL, OPT_MAXBYTES},
	{ "count",					required_argument,	NULL, OPT_COUNT},
	{ "random-type",			required_argument, 	NULL, OPT_RANDOM_TYPE},
	{ "all-random",				required_argument,	NULL, OPT_ALL_RANDOM},
	{ "type",					required_argument,	NULL, OPT_TYPE},
    { 0, 0, 0, 0 }
};

#ifdef _WIN32
BOOLEAN IsHandleRedirected(DWORD handle)
{
	HANDLE h = GetStdHandle(handle);
	if (h) {
		BY_HANDLE_FILE_INFORMATION fi;
		if (GetFileInformationByHandle(h, &fi)) {
			return TRUE;
		}
	}
	return FALSE;
}

static void attach_parent_console()
{
	BOOL outRedirected, errRedirected;

	outRedirected = IsHandleRedirected(STD_OUTPUT_HANDLE);
	errRedirected = IsHandleRedirected(STD_ERROR_HANDLE);

	if (outRedirected && errRedirected) {
		/* Both standard output and error handles are redirected.
		 * There is no point in attaching to parent process console.
		 */
		return;
	}

	if (AttachConsole(ATTACH_PARENT_PROCESS) == 0) {
		/* Console attach failed. */
		return;
	}

	/* Console attach succeeded */
	if (outRedirected == FALSE) {
		freopen("CONOUT$", "w", stdout);
	}

	if (errRedirected == FALSE) {
		freopen("CONOUT$", "w", stderr);
	}
}
#endif

static void help(const char* binname)
{
	unsigned i;
	const char** abbrev_list;
	const char** longname_list;
	unsigned list_num;

	printf("Help\n");
	printf(" Usage:\n");
	printf(" %s --extcap-interfaces\n", binname);
	printf(" %s --extcap-interface=INTERFACE --extcap-dlts\n", binname);
	printf(" %s --extcap-interface=INTERFACE --extcap-config\n", binname);
	printf(" %s --extcap-interface=INTERFACE --type dns --count 10"
			"--fifo=FILENAME --capture\n", binname);
	printf("\n\n");
	printf("  --help: print this help\n");
	printf("  --version: print the version\n");
	printf("  --verbose: verbose mode\n");
	printf("  --extcap-interfaces: list the extcap Interfaces\n");
	printf("  --extcap-dlts: list the DLTs\n");
	printf("  --extcap-interface <iface>: specify the extcap interface\n");
	printf("  --extcap-config: list the additional configuration for an interface\n");
	printf("  --capture: run the capture\n");
	printf("  --extcap-capture-filter <filter>: the capture filter\n");
	printf("  --fifo <file>: dump data to file or fifo\n");
	printf("  --maxbytes <bytes>: max bytes per packet");
	printf("  --count <num>: number of packets to generate\n");
	printf("  --random-type: one random type is choosen for all packets\n");
	printf("  --all-random: a random type is choosen for each packet\n");
	printf("  --type <type>: the packet type\n");
	printf("\n\nPacket types:\n");
	randpkt_example_list(&abbrev_list, &longname_list, &list_num);
	for (i = 0; i < list_num; i++) {
		printf("\t%-16s%s\n", abbrev_list[i], longname_list[i]);
	}
	g_free((char**)abbrev_list);
	g_free((char**)longname_list);

}

static int list_interfaces(void)
{
	printf("interface {value=%s}{display=Random packet generator}\n", RANDPKT_EXTCAP_INTERFACE);
	return EXIT_SUCCESS;
}

static int list_config(char *interface)
{
	unsigned inc = 0;
	unsigned i;
	const char** abbrev_list;
	const char** longname_list;
	unsigned list_num;

	if (!interface) {
		g_fprintf(stderr, "ERROR: No interface specified.\n");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, RANDPKT_EXTCAP_INTERFACE)) {
		errmsprintf("ERROR: interface must be %s\n", RANDPKT_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--maxbytes}{display=Max bytes in a packet}"
		"{type=unsigned}{range=1,5000}{default=5000}{tooltip=The max number of bytes in a packet}\n",
		inc++);
	printf("arg {number=%u}{call=--count}{display=Number of packets}"
		"{type=long}{default=1000}{tooltip=Number of packets to generate (-1 for infinite)}\n",
		inc++);
	printf("arg {number=%u}{call=--random-type}{display=Random type}"
		"{type=boolean}{default=false}{tooltip=The packets type is randomly choosen}\n",
		inc++);
	printf("arg {number=%u}{call=--all-random}{display=All random packets}"
		"{type=boolean}{default=false}{tooltip=Packet type for each packet is randomly choosen}\n",
		inc++);

	/* Now the types */
	printf("arg {number=%u}{call=--type}{display=Type of packet}"
		"{type=selector}{tooltip=Type of packet to generate}\n",
		inc);
	randpkt_example_list(&abbrev_list, &longname_list, &list_num);
	for (i = 0; i < list_num; i++) {
		printf("value {arg=%u}{value=%s}{display=%s}\n", inc, abbrev_list[i], longname_list[i]);
	}
	g_free((char**)abbrev_list);
	g_free((char**)longname_list);
	inc++;

	return EXIT_SUCCESS;
}

static int list_dlts(const char *interface)
{
	if (!interface) {
		printf("ERROR: No interface specified.\n");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, RANDPKT_EXTCAP_INTERFACE)) {
		printf("ERROR: interface must be %s\n", RANDPKT_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("dlt {number=147}{name=%s}{display=Generator dependent DLT}\n", RANDPKT_EXTCAP_INTERFACE);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int option_idx = 0;
	int do_capture = 0;
	int do_dlts = 0;
	int do_config = 0;
	int do_list_interfaces = 0;
	int result;
	char* fifo = NULL;
	char* interface = NULL;
	int maxbytes = 5000;
	guint64 count = 1000;
	int random_type = FALSE;
	int all_random = FALSE;
	char* type = NULL;
	int produce_type = -1;
	randpkt_example	*example;
	wtap_dumper* savedump;
	int i;

#ifdef _WIN32
	WSADATA wsaData;
#endif  /* _WIN32 */

	if (argc == 1) {
		help(argv[0]);
		return EXIT_FAILURE;
	}

#ifdef _WIN32
	attach_parent_console();
#endif  /* _WIN32 */

	for (i = 0; i < argc; i++) {
		verbose_print("%s ", argv[i]);
	}
	verbose_print("\n");

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
		switch (result) {
		case OPT_VERSION:
			printf("%u.%u.%u\n", RANDPKTDUMP_VERSION_MAJOR, RANDPKTDUMP_VERSION_MINOR, RANDPKTDUMP_VERSION_RELEASE);
			return 0;

		case OPT_VERBOSE:
			break;

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

		case OPT_CAPTURE_FILTER:
			/* currently unused */
			break;

		case OPT_FIFO:
			if (fifo)
				g_free(fifo);
			fifo = g_strdup(optarg);
			break;

		case OPT_HELP:
			help(argv[0]);
			return 0;

		case OPT_MAXBYTES:
			maxbytes = atoi(optarg);
			if (maxbytes > MAXBYTES_LIMIT) {
				errmsprintf("randpktdump: Max bytes is %u\n", MAXBYTES_LIMIT);
				return 1;
			}
			break;

		case OPT_COUNT:
			count = g_ascii_strtoull(optarg, NULL, 10);
			break;

		case OPT_RANDOM_TYPE:
			if (!g_ascii_strcasecmp("true", optarg)) {
				random_type = TRUE;
			}
			break;

		case OPT_ALL_RANDOM:
			if (!g_ascii_strcasecmp("true", optarg)) {
				all_random = TRUE;
			}
			break;

		case OPT_TYPE:
			type = g_strdup(optarg);
			break;

		case ':':
			/* missing option argument */
			printf("Option '%s' requires an argument\n", argv[optind - 1]);
			break;

		default:
			printf("Invalid option 1: %s\n", argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}

	if (optind != argc) {
		printf("Invalid option: %s\n", argv[optind]);
		return EXIT_FAILURE;
	}

	if (do_list_interfaces)
		return list_interfaces();

	if (do_config)
		return list_config(interface);

	if (do_dlts)
		return list_dlts(interface);

	/* Some sanity checks */
	if ((random_type) && (all_random)) {
		errmsprintf("You can specify only one between: --random-type, --all-random\n");
		return EXIT_FAILURE;
	}

	/* Wireshark sets the type, even when random options are selected. We don't want it */
	if (random_type || all_random) {
		g_free(type);
		type = NULL;
	}

#ifdef _WIN32
	result = WSAStartup(MAKEWORD(1,1), &wsaData);
	if (result != 0) {
		if (verbose)
			errmsprintf("ERROR: WSAStartup failed with error: %d\n", result);
		return 1;
	}
#endif  /* _WIN32 */

	if (do_capture) {
		if (!fifo) {
			errmsprintf("ERROR: No FIFO or file specified\n");
			return 1;
		}

		if (g_strcmp0(interface, RANDPKT_EXTCAP_INTERFACE)) {
			errmsprintf("ERROR: invalid interface\n");
			return 1;
		}

		randpkt_seed();

		if (!all_random) {
			produce_type = randpkt_parse_type(type);
			g_free(type);

			example = randpkt_find_example(produce_type);
			if (!example)
				return 1;

			verbose_print("Generating packets: %s\n", example->abbrev);

			randpkt_example_init(example, fifo, maxbytes);
			randpkt_loop(example, count);
			randpkt_example_close(example);
		} else {
			produce_type = randpkt_parse_type(NULL);
			example = randpkt_find_example(produce_type);
			if (!example)
				return 1;
			randpkt_example_init(example, fifo, maxbytes);

			while (count-- > 0) {
				randpkt_loop(example, 1);
				produce_type = randpkt_parse_type(NULL);

				savedump = example->dump;

				example = randpkt_find_example(produce_type);
				if (!example)
					return 1;
				example->dump = savedump;
			}
			randpkt_example_close(example);
		}
	}

	/* clean up stuff */
	if (interface)
		g_free(interface);

	if (fifo)
		g_free(fifo);

	if (type)
		g_free(type);

	return 0;
}

#ifdef _WIN32
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow) {
	return main(__argc, __argv);
}
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
