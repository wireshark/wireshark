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

#include "extcap-base.h"

#include "randpkt_core/randpkt_core.h"

#define RANDPKT_EXTCAP_INTERFACE "randpkt"
#define RANDPKTDUMP_VERSION_MAJOR "0"
#define RANDPKTDUMP_VERSION_MINOR "1"
#define RANDPKTDUMP_VERSION_RELEASE "0"

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }

static gboolean verbose = TRUE;

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_MAXBYTES,
	OPT_COUNT,
	OPT_RANDOM_TYPE,
	OPT_ALL_RANDOM,
	OPT_TYPE
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help",					no_argument,		NULL, OPT_HELP},
	{ "version",				no_argument,		NULL, OPT_VERSION},
	{ "verbose",				optional_argument,	NULL, OPT_VERBOSE},
	{ "maxbytes",				required_argument,	NULL, OPT_MAXBYTES},
	{ "count",					required_argument,	NULL, OPT_COUNT},
	{ "random-type",			required_argument, 	NULL, OPT_RANDOM_TYPE},
	{ "all-random",				required_argument,	NULL, OPT_ALL_RANDOM},
	{ "type",					required_argument,	NULL, OPT_TYPE},
    { 0, 0, 0, 0 }
};


static void help(const char* binname)
{
	unsigned i = 0;
	char** abbrev_list;
	char** longname_list;

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
	printf("  --random-type: one random type is chosen for all packets\n");
	printf("  --all-random: a random type is chosen for each packet\n");
	printf("  --type <type>: the packet type\n");
	printf("\n\nPacket types:\n");
	randpkt_example_list(&abbrev_list, &longname_list);
	while (abbrev_list[i] && longname_list[i]) {
		printf("\t%-16s%s\n", abbrev_list[i], longname_list[i]);
		i++;
	}
	printf("\n");
	g_strfreev(abbrev_list);
	g_strfreev(longname_list);

}

static int list_config(char *interface)
{
	unsigned inc = 0;
	unsigned i = 0;
	char** abbrev_list;
	char** longname_list;

	if (!interface) {
		errmsg_print("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, RANDPKT_EXTCAP_INTERFACE)) {
		errmsg_print("ERROR: interface must be %s", RANDPKT_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--maxbytes}{display=Max bytes in a packet}"
		"{type=unsigned}{range=1,5000}{default=5000}{tooltip=The max number of bytes in a packet}\n",
		inc++);
	printf("arg {number=%u}{call=--count}{display=Number of packets}"
		"{type=long}{default=1000}{tooltip=Number of packets to generate (-1 for infinite)}\n",
		inc++);
	printf("arg {number=%u}{call=--random-type}{display=Random type}"
		"{type=boolean}{default=false}{tooltip=The packets type is randomly chosen}\n",
		inc++);
	printf("arg {number=%u}{call=--all-random}{display=All random packets}"
		"{type=boolean}{default=false}{tooltip=Packet type for each packet is randomly chosen}\n",
		inc++);

	/* Now the types */
	printf("arg {number=%u}{call=--type}{display=Type of packet}"
		"{type=selector}{tooltip=Type of packet to generate}\n",
		inc);
	randpkt_example_list(&abbrev_list, &longname_list);
	while (abbrev_list[i] && longname_list[i]) {
		printf("value {arg=%u}{value=%s}{display=%s}\n", inc, abbrev_list[i], longname_list[i]);
		i++;
	}
	g_strfreev(abbrev_list);
	g_strfreev(longname_list);
	inc++;

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int option_idx = 0;
	int result;
	int maxbytes = 5000;
	guint64 count = 1000;
	int random_type = FALSE;
	int all_random = FALSE;
	char* type = NULL;
	int produce_type = -1;
	randpkt_example	*example;
	wtap_dumper* savedump;
	int i;
	int ret = EXIT_FAILURE;

#ifdef _WIN32
	WSADATA wsaData;
#endif  /* _WIN32 */

	extcap_parameters * extcap_conf = g_new0(extcap_parameters, 1);

	extcap_base_set_util_info(extcap_conf, RANDPKTDUMP_VERSION_MAJOR, RANDPKTDUMP_VERSION_MINOR, RANDPKTDUMP_VERSION_RELEASE, NULL);
	extcap_base_register_interface(extcap_conf, RANDPKT_EXTCAP_INTERFACE, "Random packet generator", 147, "Generator dependent DLT");

	if (argc == 1) {
		help(argv[0]);
		goto end;
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
			printf("%s.%s.%s\n", RANDPKTDUMP_VERSION_MAJOR, RANDPKTDUMP_VERSION_MINOR, RANDPKTDUMP_VERSION_RELEASE);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERBOSE:
			verbose = TRUE;
			break;

		case OPT_HELP:
			help(argv[0]);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_MAXBYTES:
			maxbytes = atoi(optarg);
			if (maxbytes > MAXBYTES_LIMIT) {
				errmsg_print("randpktdump: Max bytes is %d", MAXBYTES_LIMIT);
				goto end;
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
			g_free(type);
			type = g_strdup(optarg);
			break;

		case ':':
			/* missing option argument */
			errmsg_print("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			/* Handle extcap specific options */
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg))
			{
				errmsg_print("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	if (optind != argc) {
		errmsg_print("Invalid option: %s", argv[optind]);
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

	/* Some sanity checks */
	if ((random_type) && (all_random)) {
		errmsg_print("You can specify only one between: --random-type, --all-random");
		goto end;
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
			errmsg_print("ERROR: WSAStartup failed with error: %d", result);
		goto end;
	}
#endif  /* _WIN32 */

	if (extcap_conf->capture) {

		if (g_strcmp0(extcap_conf->interface, RANDPKT_EXTCAP_INTERFACE)) {
			errmsg_print("ERROR: invalid interface");
			goto end;
		}

		if (!all_random) {
			produce_type = randpkt_parse_type(type);

			example = randpkt_find_example(produce_type);
			if (!example)
				goto end;

			verbose_print("Generating packets: %s\n", example->abbrev);

			randpkt_example_init(example, extcap_conf->fifo, maxbytes);
			randpkt_loop(example, count);
			randpkt_example_close(example);
		} else {
			produce_type = randpkt_parse_type(NULL);
			example = randpkt_find_example(produce_type);
			if (!example)
				goto end;
			randpkt_example_init(example, extcap_conf->fifo, maxbytes);

			while (count-- > 0) {
				randpkt_loop(example, 1);
				produce_type = randpkt_parse_type(NULL);

				savedump = example->dump;

				example = randpkt_find_example(produce_type);
				if (!example)
					goto end;
				example->dump = savedump;
			}
			randpkt_example_close(example);
		}
		ret = EXIT_SUCCESS;
	}

end:
	/* clean up stuff */
	g_free(type);
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
