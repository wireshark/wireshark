/* randpktdump.c
 * randpktdump is an extcap tool used to generate random data for testing/educational purpose
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

#include "extcap-base.h"

#include "randpkt_core/randpkt_core.h"
#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>
#include <wsutil/please_report_bug.h>

#include <cli_main.h>
#include <ui/cmdarg_err.h>

#define RANDPKT_EXTCAP_INTERFACE "randpkt"
#define RANDPKTDUMP_VERSION_MAJOR "0"
#define RANDPKTDUMP_VERSION_MINOR "1"
#define RANDPKTDUMP_VERSION_RELEASE "0"

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_MAXBYTES,
	OPT_COUNT,
	OPT_DELAY,
	OPT_RANDOM_TYPE,
	OPT_ALL_RANDOM,
	OPT_TYPE
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help",					no_argument,		NULL, OPT_HELP},
	{ "version",				no_argument,		NULL, OPT_VERSION},
	{ "maxbytes",				required_argument,	NULL, OPT_MAXBYTES},
	{ "count",					required_argument,	NULL, OPT_COUNT},
	{ "delay",					required_argument,	NULL, OPT_DELAY},
	{ "random-type",			no_argument,		NULL, OPT_RANDOM_TYPE},
	{ "all-random",				no_argument,		NULL, OPT_ALL_RANDOM},
	{ "type",					required_argument,	NULL, OPT_TYPE},
    { 0, 0, 0, 0 }
};


static void help(extcap_parameters* extcap_conf)
{
	unsigned i = 0;
	char** abbrev_list;
	char** longname_list;

	extcap_help_print(extcap_conf);

	printf("\nPacket types:\n");
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
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, RANDPKT_EXTCAP_INTERFACE)) {
		g_warning("Interface must be %s", RANDPKT_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--maxbytes}{display=Max bytes in a packet}"
		"{type=unsigned}{range=1,5000}{default=5000}{tooltip=The max number of bytes in a packet}\n",
		inc++);
	printf("arg {number=%u}{call=--count}{display=Number of packets}"
		"{type=long}{default=1000}{tooltip=Number of packets to generate}\n",
		inc++);
	printf("arg {number=%u}{call=--delay}{display=Packet delay (ms)}"
		"{type=long}{default=0}{tooltip=Milliseconds to wait after writing each packet}\n",
		inc++);
	printf("arg {number=%u}{call=--random-type}{display=Random type}"
		"{type=boolflag}{default=false}{tooltip=The packets type is randomly chosen}\n",
		inc++);
	printf("arg {number=%u}{call=--all-random}{display=All random packets}"
		"{type=boolflag}{default=false}{tooltip=Packet type for each packet is randomly chosen}\n",
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

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

static void failure_warning_message(const char *msg_format, va_list ap)
{
	g_logv(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, msg_format, ap);
}

int main(int argc, char *argv[])
{
	char* err_msg;
	int option_idx = 0;
	int result;
	guint16 maxbytes = 5000;
	guint64 count = 1000;
	guint64 packet_delay_ms = 0;
	int random_type = FALSE;
	int all_random = FALSE;
	char* type = NULL;
	int produce_type = -1;
	randpkt_example	*example;
	wtap_dumper* savedump;
	int ret = EXIT_FAILURE;

	extcap_parameters * extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;

	cmdarg_err_init(failure_warning_message, failure_warning_message);

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

	help_url = data_file_url("randpktdump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], RANDPKTDUMP_VERSION_MAJOR, RANDPKTDUMP_VERSION_MINOR,
		RANDPKTDUMP_VERSION_RELEASE, help_url);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, RANDPKT_EXTCAP_INTERFACE, "Random packet generator", 147, "Generator dependent DLT");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --type dns --count 10 "
		"--fifo=FILENAME --capture\n", argv[0], argv[0], RANDPKT_EXTCAP_INTERFACE, argv[0], RANDPKT_EXTCAP_INTERFACE,
		argv[0], RANDPKT_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);

	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--maxbytes <bytes>", "max bytes per pack");
	extcap_help_add_option(extcap_conf, "--count <num>", "number of packets to generate");
	extcap_help_add_option(extcap_conf, "--delay <ms>", "milliseconds to wait after writing each packet");
	extcap_help_add_option(extcap_conf, "--random-type", "one random type is chosen for all packets");
	extcap_help_add_option(extcap_conf, "--all-random", "a random type is chosen for each packet");
	extcap_help_add_option(extcap_conf, "--type <type>", "the packet type");

	if (argc == 1) {
		help(extcap_conf);
		goto end;
	}

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
		switch (result) {
		case OPT_VERSION:
			extcap_version_print(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_HELP:
			help(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_MAXBYTES:
			if (!ws_strtou16(optarg, NULL, &maxbytes)) {
				g_warning("Invalid parameter maxbytes: %s (max value is %u)",
					optarg, G_MAXUINT16);
				goto end;
			}
			break;

		case OPT_COUNT:
			if (!ws_strtou64(optarg, NULL, &count)) {
				g_warning("Invalid packet count: %s", optarg);
				goto end;
			}
			break;

		case OPT_DELAY:
			if (!ws_strtou64(optarg, NULL, &packet_delay_ms)) {
				g_warning("Invalid packet delay: %s", optarg);
				goto end;
			}
			break;

		case OPT_RANDOM_TYPE:
			random_type = TRUE;
			break;

		case OPT_ALL_RANDOM:
			all_random = TRUE;
			break;

		case OPT_TYPE:
			g_free(type);
			type = g_strdup(optarg);
			break;

		case ':':
			/* missing option argument */
			g_warning("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			/* Handle extcap specific options */
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg))
			{
				g_warning("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	extcap_cmdline_debug(argv, argc);

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
		g_warning("You can specify only one between: --random-type, --all-random");
		goto end;
	}

	/* Wireshark sets the type, even when random options are selected. We don't want it */
	if (random_type || all_random) {
		g_free(type);
		type = NULL;
	}

	err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		g_warning("ERROR: %s", err_msg);
		g_free(err_msg);
		g_warning("%s", please_report_bug());
		goto end;
	}

	if (extcap_conf->capture) {

		if (g_strcmp0(extcap_conf->interface, RANDPKT_EXTCAP_INTERFACE)) {
			g_warning("ERROR: invalid interface");
			goto end;
		}

		wtap_init(FALSE);

		if (!all_random) {
			produce_type = randpkt_parse_type(type);

			example = randpkt_find_example(produce_type);
			if (!example)
				goto end;

			g_debug("Generating packets: %s", example->abbrev);

			randpkt_example_init(example, extcap_conf->fifo, maxbytes);
			randpkt_loop(example, count, packet_delay_ms);
			randpkt_example_close(example);
		} else {
			produce_type = randpkt_parse_type(NULL);
			example = randpkt_find_example(produce_type);
			if (!example)
				goto end;
			randpkt_example_init(example, extcap_conf->fifo, maxbytes);

			while (count-- > 0) {
				randpkt_loop(example, 1, packet_delay_ms);
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
